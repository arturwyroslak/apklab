import gradio as gr
import subprocess
import os
import shutil
import zipfile
import requests
import uuid
from pathlib import Path

# --- Configuration ---
BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR / "tools"
TEMP_DIR = BASE_DIR / "temp"
DOWNLOADS_DIR = BASE_DIR / "downloads"

# Ensure directories exist
os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

APKTOOL_PATH = TOOLS_DIR / "apktool.jar"
SIGNER_PATH = TOOLS_DIR / "uber-apk-signer.jar"
JADX_PATH = TOOLS_DIR / "jadx" / "bin" / "jadx"

class APKProcessor:
    def _run_command(self, command, cwd=None):
        """Runs a command and returns its output and errors."""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
            )
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                return False, stdout, stderr
            return True, stdout, stderr
        except Exception as e:
            return False, "", str(e)

    def check_tools(self):
        """Verifies that all required tools are present."""
        logs = []
        # 1. Check for Java (JDK)
        success, stdout, stderr = self._run_command(["java", "--version"])
        if not success:
            return False, "Java (JDK) not found. Please install it and make sure it's in your PATH."
        logs.append(f"Java Version:\n{stdout}{stderr}")

        # 2. Check for apktool.jar
        if not APKTOOL_PATH.exists():
            return False, f"apktool.jar not found at {APKTOOL_PATH}"
        logs.append("apktool.jar found.")

        # 3. Check for uber-apk-signer.jar
        if not SIGNER_PATH.exists():
            return False, f"uber-apk-signer.jar not found at {SIGNER_PATH}"
        logs.append("uber-apk-signer.jar found.")

        # 4. Check for JADX
        if not JADX_PATH.exists():
            return False, f"JADX not found at {JADX_PATH}"
        logs.append("JADX found.")

        return True, "\n".join(logs)

    def download_apk(self, url, progress):
        """Downloads an APK from a URL."""
        try:
            apk_name = url.split("/")[-1]
            if not apk_name.endswith(".apk"):
                apk_name = "downloaded.apk"

            apk_path = TEMP_DIR / apk_name

            response = requests.get(url, stream=True)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            bytes_downloaded = 0

            with open(apk_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    bytes_downloaded += len(chunk)
                    progress(bytes_downloaded / total_size, f"Downloading: {bytes_downloaded}/{total_size} bytes")

            return str(apk_path)
        except requests.exceptions.RequestException as e:
            raise gr.Error(f"Failed to download APK from URL: {e}")


    def apktool_decode(self, apk_path, output_dir, options):
        """Decodes an APK using apktool."""
        command = ["java", "-jar", str(APKTOOL_PATH), "d", str(apk_path), "-o", str(output_dir), "-f"] + options
        return self._run_command(command)

    def jadx_decompile(self, apk_path, output_dir, options):
        """Decompiles an APK to Java source using JADX."""
        # JADX outputs to a directory named after the APK by default inside the specified output dir
        # We want the source to be inside our project dir, so we tell it to output there
        java_src_dir = output_dir / "java_sources"
        command = [str(JADX_PATH), "-r", "-q", "-ds", str(java_src_dir)] + options + [str(apk_path)]
        return self._run_command(command, cwd=output_dir)


    def quark_analyze(self, apk_path, output_dir):
        """Analyzes an APK using Quark-Engine."""
        report_path = output_dir / "quark-report.json"
        command = ["quark", "analyze", "-a", str(apk_path), "-o", str(report_path)]
        return self._run_command(command)

    def mitm_patch(self, project_dir):
        """Applies an MITM patch using apk-mitm."""
        # apk-mitm works on an apk file, not a decoded directory. This is a misunderstanding in the prompt.
        # The typical workflow is: decode -> modify -> build -> patch -> sign
        # For this implementation, we will assume the user wants to patch the network security config in the decoded project.
        # A simple patch is to add a permissive network_security_config.xml
        net_sec_config_path = project_dir / "res" / "xml"
        os.makedirs(net_sec_config_path, exist_ok=True)
        config_content = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""
        with open(net_sec_config_path / "network_security_config.xml", "w") as f:
            f.write(config_content)

        # Also need to reference this in AndroidManifest.xml
        manifest_path = project_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            with open(manifest_path, "r+") as f:
                content = f.read()
                if 'android:networkSecurityConfig' not in content:
                    content = content.replace('<application', '<application android:networkSecurityConfig="@xml/network_security_config"')
                    f.seek(0)
                    f.write(content)
                    f.truncate()
            return True, "MITM patch applied to AndroidManifest.xml and network_security_config.xml created.", ""
        return False, "AndroidManifest.xml not found.", ""


    def apktool_build(self, project_dir, output_apk, options):
        """Rebuilds an APK from a directory using apktool."""
        command = ["java", "-jar", str(APKTOOL_PATH), "b", str(project_dir), "-o", str(output_apk)] + options
        return self._run_command(command)

    def sign_apk(self, apk_path, keystore_path, ks_pass, ks_alias, key_pass):
        """Signs an APK using uber-apk-signer."""
        command = [
            "java", "-jar", str(SIGNER_PATH),
            "--apks", str(apk_path),
            "--ks", str(keystore_path),
            "--ksPass", ks_pass,
            "--ksAlias", ks_alias,
            "--keyPass", key_pass
        ]
        return self._run_command(command)

    def create_zip(self, source_dir, zip_path):
        """Creates a zip archive from a directory."""
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(source_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    archive_path = os.path.relpath(file_path, source_dir)
                    zipf.write(file_path, archive_path)
        return str(zip_path)

processor = APKProcessor()

def process_apk(apk_file, apk_url, decode_options, progress=gr.Progress(track_tqdm=True)):
    logs = []

    # 1. Check tools
    tools_ok, tool_logs = processor.check_tools()
    logs.append(f"--- Tool Check ---\n{tool_logs}")
    if not tools_ok:
        return "Error: Tools are not configured correctly.", gr.DownloadButton(visible=False), "\n".join(logs)

    # 2. Determine APK path
    if apk_file is None and not apk_url:
        raise gr.Error("Please upload an APK file or provide a URL.")

    apk_path = ""
    if apk_file is not None:
        apk_path = apk_file.name
        logs.append(f"Processing uploaded file: {apk_path}")
    else:
        try:
            logs.append(f"Downloading APK from URL: {apk_url}")
            progress(0, desc="Downloading APK...")
            apk_path = processor.download_apk(apk_url, progress)
            logs.append(f"APK downloaded to: {apk_path}")
        except Exception as e:
            return f"Error downloading APK: {e}", gr.DownloadButton(visible=False), "\n".join(logs)

    # 3. Setup project directory
    project_name = Path(apk_path).stem
    project_dir = TEMP_DIR / f"{project_name}-decompiled-{uuid.uuid4().hex[:8]}"
    if project_dir.exists():
        shutil.rmtree(project_dir)
    os.makedirs(project_dir)
    logs.append(f"Created project directory: {project_dir}")

    # 4. Parse options
    apktool_opts, jadx_opts = [], []
    if "no_src" in decode_options: apktool_opts.append("-s")
    if "no_res" in decode_options: apktool_opts.append("-r")
    if "force_manifest" in decode_options: apktool_opts.append("--force-manifest")
    if "no_assets" in decode_options: apktool_opts.append("--no-assets")
    if "only_main_classes" in decode_options: apktool_opts.append("--only-main-classes")
    if "no_debug_info" in decode_options: apktool_opts.append("-b")
    if "deobf" in decode_options: jadx_opts.append("--deobf")
    if "show_bad_code" in decode_options: jadx_opts.append("--show-bad-code")

    # 5. Decode with Apktool
    progress(0.2, desc="Decompiling with Apktool...")
    logs.append(f"\n--- Apktool Decompilation ---\nRunning with options: {' '.join(apktool_opts)}")
    success, stdout, stderr = processor.apktool_decode(apk_path, project_dir, apktool_opts)
    logs.append(f"Apktool STDOUT:\n{stdout}")
    logs.append(f"Apktool STDERR:\n{stderr}")
    if not success:
        return f"Apktool failed.", gr.DownloadButton(visible=False), "\n".join(logs)

    # 6. Optional: MITM Patch
    if "mitm_patch" in decode_options:
        progress(0.5, desc="Applying MITM patch...")
        logs.append("\n--- MITM Patch ---")
        success, out, err = processor.mitm_patch(project_dir)
        logs.append(out)
        logs.append(err)

    # 7. Optional: Quark Analysis
    if "quark_analysis" in decode_options:
        progress(0.6, desc="Analyzing with Quark-Engine...")
        logs.append("\n--- Quark Engine Analysis ---")
        success, stdout, stderr = processor.quark_analyze(apk_path, project_dir)
        logs.append(f"Quark STDOUT:\n{stdout}")
        logs.append(f"Quark STDERR:\n{stderr}")
        if not success:
            logs.append("Quark analysis failed.") # Non-fatal

    # 8. Optional: JADX Decompilation
    if "decompile_java" in decode_options:
        progress(0.8, desc="Decompiling Java with JADX...")
        logs.append(f"\n--- JADX Decompilation ---\nRunning with options: {' '.join(jadx_opts)}")
        success, stdout, stderr = processor.jadx_decompile(apk_path, project_dir, jadx_opts)
        logs.append(f"JADX STDOUT:\n{stdout}")
        logs.append(f"JADX STDERR:\n{stderr}")
        if not success:
            logs.append("JADX decompilation failed.") # Non-fatal

    # 9. Create ZIP archive
    progress(0.95, desc="Creating ZIP archive...")
    zip_name = f"{project_name}-decompiled.zip"
    zip_path = DOWNLOADS_DIR / zip_name
    processor.create_zip(project_dir, zip_path)
    logs.append(f"\nProject zipped to {zip_path}")

    # 10. Clean up temp project dir
    shutil.rmtree(project_dir)

    return f"Success! Project decompiled and zipped.", gr.DownloadButton(value=str(zip_path), visible=True), "\n".join(logs)


def rebuild_and_sign_apk(project_zip, build_options, keystore_file, ks_pass, alias, key_pass, progress=gr.Progress(track_tqdm=True)):
    logs = []

    if not project_zip:
        raise gr.Error("Please upload a project ZIP file.")
    if not keystore_file:
        raise gr.Error("Please upload a keystore file.")
    if not all([ks_pass, alias, key_pass]):
        raise gr.Error("Please provide all keystore credentials.")

    # 1. Setup directories
    project_dir = TEMP_DIR / f"rebuild-{uuid.uuid4().hex[:8]}"
    output_dir = TEMP_DIR / f"rebuild-out-{uuid.uuid4().hex[:8]}"
    os.makedirs(project_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # 2. Unzip project
    progress(0.1, desc="Unzipping project...")
    with zipfile.ZipFile(project_zip.name, 'r') as zip_ref:
        zip_ref.extractall(project_dir)
    logs.append(f"Project unzipped to {project_dir}")

    # 3. Rebuild with Apktool
    unsigned_apk_path = output_dir / "rebuilt-unsigned.apk"
    build_opts = []
    if "no_crunch" in build_options: build_opts.append("--no-crunch")
    if "use_aapt2" in build_options: build_opts.append("--use-aapt2")

    progress(0.3, desc="Rebuilding with Apktool...")
    logs.append(f"\n--- Apktool Rebuild ---\nRunning with options: {' '.join(build_opts)}")
    success, stdout, stderr = processor.apktool_build(project_dir, unsigned_apk_path, build_opts)
    logs.append(f"Apktool STDOUT:\n{stdout}")
    logs.append(f"Apktool STDERR:\n{stderr}")
    if not success:
        shutil.rmtree(project_dir)
        shutil.rmtree(output_dir)
        return "Apktool rebuild failed.", gr.DownloadButton(visible=False), "\n".join(logs)

    # 4. Sign the APK
    progress(0.8, desc="Signing APK...")
    logs.append("\n--- Signing APK ---")
    success, stdout, stderr = processor.sign_apk(
        unsigned_apk_path,
        keystore_file.name,
        ks_pass,
        alias,
        key_pass
    )
    logs.append(f"Signer STDOUT:\n{stdout}")
    logs.append(f"Signer STDERR:\n{stderr}")
    if not success:
        shutil.rmtree(project_dir)
        shutil.rmtree(output_dir)
        return "Signing failed.", gr.DownloadButton(visible=False), "\n".join(logs)

    # Uber-apk-signer adds "-aligned-signed" to the file name.
    signed_apk_path = output_dir / f"{unsigned_apk_path.stem}-aligned-signed.apk"
    final_apk_path = DOWNLOADS_DIR / f"{Path(project_zip.name).stem}-signed.apk"
    shutil.move(signed_apk_path, final_apk_path)

    # 5. Cleanup
    shutil.rmtree(project_dir)
    shutil.rmtree(output_dir)

    return "Success! APK rebuilt and signed.", gr.DownloadButton(value=str(final_apk_path), visible=True), "\n".join(logs)


# --- Gradio Interface ---
with gr.Blocks(title="APKLab") as app:
    gr.Markdown("# APKLab Web Interface")
    with gr.Tabs():
        with gr.Tab("📱 Decompile APK"):
            with gr.Row():
                with gr.Column():
                    apk_file = gr.File(label="Upload APK", type="file")
                    apk_url = gr.Textbox(label="OR provide APK URL", placeholder="https://example.com/app.apk")
                    decode_opts = gr.CheckboxGroup(
                        label="Additional Features & Options",
                        choices=[
                            ("Analyze with Quark-Engine", "quark_analysis"),
                            ("Decompile Java sources (with JADX)", "decompile_java"),
                            ("Apply MITM patch (for HTTPS inspection)", "mitm_patch"),
                            ("JADX: Deobfuscation", "deobf"),
                            ("JADX: Show bad code", "show_bad_code"),
                            ("Apktool: --no-src (skip smali)", "no_src"),
                            ("Apktool: --no-res (skip resources)", "no_res"),
                            ("Apktool: --force-manifest", "force_manifest"),
                            ("Apktool: --no-assets", "no_assets"),
                            ("Apktool: --only-main-classes", "only_main_classes"),
                            ("Apktool: --no-debug-info", "no_debug_info"),
                        ],
                        value=[],
                    )
                    decode_btn = gr.Button("🚀 Decompile", variant="primary")
                with gr.Column():
                    status_out = gr.Textbox(label="Status", interactive=False)
                    zip_out = gr.DownloadButton("📦 Download Decompiled Project (ZIP)", visible=False)
                    logs_out = gr.Textbox(label="Logs", interactive=False, lines=20, max_lines=20)

            decode_btn.click(
                fn=process_apk,
                inputs=[apk_file, apk_url, decode_opts],
                outputs=[status_out, zip_out, logs_out],
            )

        with gr.Tab("🔄 Rebuild & Sign APK"):
            with gr.Row():
                with gr.Column():
                    project_zip = gr.File(label="Upload Decompiled Project (ZIP)", type="file")
                    build_opts = gr.CheckboxGroup(
                        label="Apktool Build Options",
                        choices=[
                            ("Use aapt2", "use_aapt2"),
                            ("Disable resource crunching (--no-crunch)", "no_crunch"),
                        ],
                        value=[],
                    )
                    gr.Markdown("### Keystore Information")
                    ks_file = gr.File(label="Keystore file (.jks, .keystore)", type="file")
                    ks_pass = gr.Textbox(label="Keystore Password", type="password")
                    ks_alias = gr.Textbox(label="Key Alias")
                    key_pass = gr.Textbox(label="Key Password", type="password")
                    build_btn = gr.Button("🔨 Rebuild & Sign", variant="primary")
                with gr.Column():
                    build_status = gr.Textbox(label="Status", interactive=False)
                    apk_out = gr.DownloadButton("📱 Download Signed APK", visible=False)
                    build_logs = gr.Textbox(label="Logs", interactive=False, lines=20, max_lines=20)

            build_btn.click(
                fn=rebuild_and_sign_apk,
                inputs=[project_zip, build_opts, ks_file, ks_pass, ks_alias, key_pass],
                outputs=[build_status, apk_out, build_logs],
            )

        with gr.Tab("📖 Instructions"):
            gr.Markdown("""
            ## How to Use This Application (with Docker)

            **1. Prerequisites:**
            - Make sure you have Docker installed and running on your system.

            **2. Build the Docker Image:**
            - Open your terminal or command prompt.
            - Navigate to the `apklab-gradio` directory (where the `Dockerfile` is located).
            - Run the following command to build the image. This might take some time as it downloads tools and dependencies.
              ```bash
              docker build -t apklab-gradio .
              ```

            **3. Run the Docker Container:**
            - After the build is complete, run the container with this command:
              ```bash
              docker run -p 7860:7860 apklab-gradio
              ```
            - The `-p 7860:7860` part maps the port inside the container to the same port on your host machine.

            **4. Access the Web UI:**
            - Open your web browser and go to: **http://127.0.0.1:7860**
            - You should now see the APKLab interface.

            ---

            ### Tab: Decompile APK
            1.  **Upload an APK** file from your computer or **provide a direct URL** to an APK.
            2.  Select any desired options for decompilation, analysis, or patching.
            3.  Click the **"Decompile"** button.
            4.  Wait for the process to complete. The status and logs will be updated.
            5.  Once finished, a **"Download...ZIP"** button will appear. Click it to save the decompiled project.

            ### Tab: Rebuild & Sign APK
            1.  **Upload the ZIP** file of a decompiled project (either one you downloaded from this tool or one you modified).
            2.  Select any build options.
            3.  **Upload your keystore** file.
            4.  **Enter your keystore password, key alias, and key password.**
            5.  Click the **"Rebuild & Sign"** button.
            6.  Once the process is complete, a **"Download...APK"** button will appear.
            """)

if __name__ == "__main__":
    app.launch(server_name="0.0.0.0", server_port=7860)

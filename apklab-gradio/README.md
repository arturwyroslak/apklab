# APKLab Gradio

This project is a web-based interface for decompiling, analyzing, modifying, and rebuilding Android APK files. It uses Gradio for the UI and a set of powerful backend tools, all containerized with Docker for easy setup and execution.

This is a web-based version of the original [APKLab VS Code extension](https://github.com/APKLab/APKLab).

## Features

- **Decompile APKs**: Use Apktool to decompile APKs into smali code and resources.
- **Decompile to Java**: Use JADX to decompile the application to Java source code for easier analysis.
- **Security Analysis**: Run Quark-Engine to identify potential security vulnerabilities.
- **MITM Patching**: Automatically apply a patch to the `AndroidManifest.xml` and add a network security configuration to allow for HTTPS traffic inspection.
- **Rebuild & Sign**: Rebuild a modified project directory back into an APK and sign it with your own keystore.

## Prerequisites

- [Docker](https://www.docker.com/get-started) must be installed and running on your system.

## Installation & Setup

The entire application runs inside a Docker container, so there's no need to install Java, Python, or any of the reverse engineering tools on your host machine.

**1. Build the Docker Image**

Open your terminal, navigate to this directory (`apklab-gradio`), and run the following command. This will download the base image, install all dependencies, and set up the tools. This may take several minutes.

```bash
docker build -t apklab-gradio .
```

**2. Run the Docker Container**

Once the image is built, you can start the application with this command:

```bash
docker run --rm -p 7860:7860 apklab-gradio
```

- `--rm`: This flag automatically removes the container when it's stopped.
- `-p 7860:7860`: This maps port 7860 from the container to port 7860 on your computer.

## How to Use

After running the container, open your web browser and navigate to:

**http://127.0.0.1:7860**

You will be greeted with the APKLab web interface, which has three tabs.

### Tab 1: Decompile APK

This tab is for reverse engineering an APK file.

1.  **Provide an APK**: You can either upload an APK file directly from your computer or paste a direct URL to an APK file.
2.  **Select Options**:
    - **Analyze with Quark-Engine**: Performs a security analysis and includes the report in the output.
    - **Decompile Java sources (with JADX)**: Decompiles the code to Java and saves it in a `java_sources` folder.
    - **Apply MITM patch**: Adds a network security configuration to allow interception of HTTPS traffic.
    - **JADX/Apktool options**: Fine-tune the decompilation process with various options from the underlying tools.
3.  **Decompile**: Click the "🚀 Decompile" button to start the process.
4.  **Download**: Once complete, a "📦 Download...ZIP" button will appear. Click it to download a ZIP archive of the decompiled project.

### Tab 2: Rebuild & Sign APK

This tab is for compiling a project folder back into a runnable APK file.

1.  **Upload Project**: Upload the ZIP file of a decompiled project (you can modify the contents of the ZIP before uploading).
2.  **Build Options**: Select any relevant build options for Apktool.
3.  **Provide Keystore**: Upload your `.jks` or `.keystore` file and provide the corresponding passwords and key alias.
4.  **Rebuild**: Click the "🔨 Rebuild & Sign" button.
5.  **Download**: Once complete, a "📱 Download Signed APK" button will appear.

### Tab 3: Instructions

This tab contains a summary of these instructions for quick reference within the application itself.

## Tools Used

- [Gradio](https://www.gradio.app/)
- [Apktool](https://github.com/iBotPeaches/Apktool)
- [JADX](https://github.com/skylot/jadx)
- [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)
- [Quark-Engine](https://github.com/quark-engine/quark-engine)
- [apk-mitm](https://github.com/shroudedcode/apk-mitm) (Note: The implementation here manually applies the patch to the decoded source).

## Screenshots

*(Placeholder for screenshots of the Gradio interface)*

![Decompile Tab](https://via.placeholder.com/800x400.png?text=Decompile+Tab+Screenshot)
![Rebuild Tab](https://via.placeholder.com/800x400.png?text=Rebuild+Tab+Screenshot)

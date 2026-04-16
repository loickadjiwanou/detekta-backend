# 📱 APK Audit Guide - Detekta

This guide takes you step-by-step through performing your first real mobile application audit (**APK/IPA**) using Detekta and MobSF.

---

### 🚀 Step 1: Start the Analysis Engine (MobSF)
Open your terminal in the project directory and launch the MobSF container:

```bash
cd detekta-backend/mobsf
docker compose up -d
```
> [!NOTE]
> Wait approximately **15-30 seconds** for MobSF to initialize its internal databases before starting a scan.

---

### 🛠️ Step 2: Start Detekta
Ensure that both backend and frontend services are active:

*   **Backend**:
    ```bash
    cd detekta-backend
    uvicorn server:app --reload
    ```
*   **Frontend**:
    ```bash
    cd detekta-frontend
    yarn start
    ```

---

### 🔍 Step 3: Create the Audit in the Interface
1.  Log in to Detekta ([http://localhost:3000](http://localhost:3000)).
2.  Click the **"New Audit"** button.
3.  Select the **"Mobile Audit"** tab.
4.  Click the upload area and select your **.apk** (or .ipa) file.
5.  Once the file is loaded, click **"Start Audit"**.

---

### 📊 Step 4: Follow the Real-Time Analysis
You will be redirected to the audit details page. Observe the logs in the integrated terminal:

- **`Uploading to MobSF engine...`**: Detekta is sending your file to the Docker container.
- **`Starting static analysis (jadx, apktool)...`**: MobSF is decompiling and analyzing the source code.
- **`Live Tests`**: Click the **"View Live Tests"** button to see the security checkpoints (Manifest, Certificates, Secrets, Code) being validated in real-time.

---

### 📄 Step 5: View and Export the Report
Once the analysis is complete (100%):

1.  Click the **"View Report"** button.
2.  Review the interactive **Security Score** and the AI-generated strategic analysis.
3.  Click the **"Download PDF"** button to obtain your professional report, formatted according to your selected theme (Dark or Light).

---

### 💡 Tip
> [!TIP]
> **Did you know?** You can check the MobSF status directly at [http://localhost:8008](http://localhost:8008). While this is the interface for the underlying tool, Detekta handles all orchestration to provide you with a unified experience.

---
*Detekta © 2026 — See every flaw. Fix every risk.*
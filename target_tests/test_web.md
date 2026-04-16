# 🌐 Web Audit Guide - Detekta

This guide takes you step-by-step through performing your first security audit on a web application via its URL.

---

### 🛠️ Step 1: Start Detekta
Before starting, ensure both backend and frontend services are active:

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

### 🔍 Step 2: Create the Audit in the Interface
1.  Log in to Detekta ([http://localhost:3000](http://localhost:3000)).
2.  Click the **"New Audit"** button.
3.  Select the **"Web Audit"** tab.
4.  Enter the target URL (e.g., `https://example.com`).
5.  Choose the scan depth (**Quick**, **Standard**, or **Deep**).
6.  Assign an **Audit Name** (e.g., "Main Website Scan") for easy identification.
7.  Click **"Start Audit"**.

---

### 📊 Step 3: Follow the Real-Time Analysis
You will be redirected to the audit details page. Monitor the progress:

- **`Initializing crawler...`**: Detekta is exploring the structure of your site.
- **`Running vulnerability scans...`**: Launching security tests (XSS, SQLi, CSRF, Security Headers).
- **`Live Tests`**: Watch the security checkpoints being validated in real-time in the details modal.

---

### 📄 Step 4: View and Export the Report
Once the scan reaches 100%:

1.  Click the **"View Report"** button.
2.  **Global Analysis**: Discover your security score and strategic summary.
3.  **Vulnerability Details**: Examine each finding with its severity, impact, and most importantly, the **remediation recommendation**.
4.  **Export**: Download the report in **PDF** or **HTML** format to share with your technical teams.

---

### ⚠️ Important Notice
> [!IMPORTANT]
> **Ethics & Legality**: Only audit sites that you own or for which you have explicit permission. Security auditing should always be conducted within a legal and responsible framework.

---
*Detekta © 2026 — See every flaw. Fix every risk.*

# Malicious Email Scorer — Gmail Add-on

## Quick Deploy (Sprint 1)

### Step 1: Create the Apps Script project
1. Go to [script.google.com](https://script.google.com)
2. Click **New project**
3. Name it `Malicious Email Scorer`

### Step 2: Copy the code
1. In the Apps Script editor, replace the contents of `Code.gs` with the contents of `Code.js` from this repo
2. Click the **gear icon** (Project Settings) on the left sidebar
3. Check **"Show appsscript.json manifest file in editor"**
4. Go back to the Editor, click on `appsscript.json`, and replace its contents with the `appsscript.json` from this repo

### Step 3: Test as a Gmail Add-on
1. Click **Deploy** → **Test deployments**
2. Under **Application type**, select **Gmail Add-on**
3. Click **Execute**
4. Open [Gmail](https://mail.google.com) in a new tab
5. Click on any email — you should see the **Malicious Email Scorer** panel in the right sidebar showing the email subject and sender

### Alternative: Deploy with clasp (CLI)
```bash
npm install -g @google/clasp
clasp login
clasp create --title "Malicious Email Scorer" --type standalone
# This creates the project and updates .clasp.json with your scriptId
clasp push
```
Then go to script.google.com, open the project, and follow Step 3 above.

---

*Sprint 1: Minimal add-on that displays email subject and sender.*

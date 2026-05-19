https://drive.google.com/uc?export=download&id=1jjRZ_2GoZrDqvGLrrnNrwQh-t4GkGl4I
https://drive.google.com/uc?export=download&id=1DCXs3N6SxfJpm7w979cXVp9q3enyNw8P


* **Host:** `192.168.122.45` *(The FTD's new IP)*
* **Display Name:** Give it a cool name, like `SOC-FTD-01`
* **Registration Key:** `LabKey123` *(Must match the secret we just made)*
* **Domain:** Global *(Leave default)*

### 🛠️ Step 3: The Access Control Policy (ACP)

The FMC will not let you add a firewall without assigning a set of rules to it. Since this is brand new, you don't have any rules yet.

1. Next to the **Access Control Policy** dropdown, click the **New Policy** button (it sometimes looks like a little `+` icon or just text).
2. Name the policy something like `Base-Lab-Policy`.
3. Set the Default Action to **Block all traffic** or **Network Discovery** (either is fine for right now).
4. Save the policy, and make sure it is selected in the dropdown.

### 🛠️ Step 4: Smart Licensing

At the bottom of the popup, you will see checkboxes for Smart Licensing (Malware, Threat, URL Filtering).

* Check all the boxes to enable your evaluation licenses so you can play with the fun security features later!

### 🚀 Step 5: Register!

Click the blue **Register** button at the bottom.

A spinning loading icon will appear, and the FMC will reach across the KVM virtual switch to talk to the FTD. It takes about 2 to 5 minutes for the FMC to pull down the FTD's interfaces and establish the secure tunnel. When it finishes, your FTD will magically populate right there in your Device Management list with a green "Normal" status!
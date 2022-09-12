# Microsoft-Sentinel-Bulk-Delete-Threat-Indicators
Delete Threat Indicators in Bulk

# How to use
1. Download the Tool  
   [![Download](./images/Download.png)](https://github.com/sreedharande/Microsoft-Sentinel-Bulk-Delete-Threat-Indicators/archive/refs/heads/main.zip)

2. Extract the folder and open "Bulk_Delete_Threat_Indicators.ps1" either in Visual Studio Code/PowerShell(Admin)

   **Note**  
   The script runs from the user's machine. You must allow PowerShell script execution. To do so, run the following command:
   
   ```PowerShell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass  
   ```  

3. Run the script using the following command  
   ```  
   .\Bulk_Delete_Threat_Indicators.ps1 -TenantID xxxx `
                        
   ```
4. Enter TI Source

5. This script will retreive a max page size of 100 at a time, the fetch indicators call can only fetch a list of 100 indicators for any workspace. However, since a workspace can have more than 100 indicators for a particular source, it deletes 100 indicators repeatedly, until all indicators have been deleted.
	


	
# Questions ❓ / Issues 🙋‍♂️ / Feedback 🗨
Post [here](https://github.com/sreedharande/Microsoft-Sentinel-Bulk-Delete-Threat-Indicators/issues).

Contributions are welcome! 👏

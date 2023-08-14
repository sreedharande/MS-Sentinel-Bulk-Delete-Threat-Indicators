<#       
  	THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SCRIPT OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

    .SYNOPSIS
        This PowerShell script deletes Threat Indicators from Sentinel Portal in bulk 
        

    .DESCRIPTION
        It performs the following actions:
            1. Gets all Threat Indicators for a particular source filter
            2. Loop through each Threat Indicator and deletes Threat Indicator          
    
    .PARAMETER TenantId
        Enter Azure Tenant Id (required)  

    .NOTES
        AUTHOR: Sreedhar Ande
        LASTEDIT: 9/12/2022

    .EXAMPLE
        .\Bulk_Delete_Threat_Indicators.ps1 -TenantId xxxx
#>

#region UserInputs

param(
    [parameter(Mandatory = $true, HelpMessage = "Enter your Tenant Id")]
    [string] $TenantID
)

#endregion UserInputs
      
#region HelperFunctions

function Write-Log {
    <#
    .DESCRIPTION 
    Write-Log is used to write information to a log file and to the console.
    
    .PARAMETER Severity
    parameter specifies the severity of the log message. Values can be: Information, Warning, or Error. 
    #>

    [CmdletBinding()]
    param(
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [string]$LogFileName,
 
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information'
    )
    # Write the message out to the correct channel											  
    switch ($Severity) {
        "Information" { Write-Host $Message -ForegroundColor Green }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
    } 											  
    try {
        [PSCustomObject]@{
            Time     = (Get-Date -f g)
            Message  = $Message
            Severity = $Severity
        } | Export-Csv -Path "$PSScriptRoot\$LogFileName" -Append -NoTypeInformation -Force
    }
    catch {
        Write-Error "An error occurred in Write-Log() method" -ErrorAction SilentlyContinue		
    }    
}

function Get-RequiredModules {
    <#
    .DESCRIPTION 
    Get-Required is used to install and then import a specified PowerShell module.
    
    .PARAMETER Module
    parameter specifices the PowerShell module to install. 
    #>

    [CmdletBinding()]
    param (        
        [parameter(Mandatory = $true)] $Module        
    )
    
    try {
        $installedModule = Get-InstalledModule -Name $Module -ErrorAction SilentlyContinue       

        if ($null -eq $installedModule) {
            Write-Log -Message "The $Module PowerShell module was not found" -LogFileName $LogFileName -Severity Warning
            #check for Admin Privleges
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

            if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                #Not an Admin, install to current user            
                Write-Log -Message "Can not install the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                Write-Log -Message "Installing $Module module to current user Scope" -LogFileName $LogFileName -Severity Warning
                
                Install-Module -Name $Module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
            else {
                #Admin, install to all users																		   
                Write-Log -Message "Installing the $Module module to all users" -LogFileName $LogFileName -Severity Warning
                Install-Module -Name $Module -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
        }
        else {
            if ($UpdateAzModules) {
                Write-Log -Message "Checking updates for module $Module" -LogFileName $LogFileName -Severity Information
                $currentVersion = [Version](Get-InstalledModule | Where-Object {$_.Name -eq $Module}).Version
                # Get latest version from gallery
                $latestVersion = [Version](Find-Module -Name $Module).Version
                if ($currentVersion -ne $latestVersion) {
                    #check for Admin Privleges
                    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

                    if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                        #install to current user            
                        Write-Log -Message "Can not update the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                        Write-Log -Message "Updating $Module from [$currentVersion] to [$latestVersion] to current user Scope" -LogFileName $LogFileName -Severity Warning
                        Update-Module -Name $Module -RequiredVersion $latestVersion -Force
                    }
                    else {
                        #Admin - Install to all users																		   
                        Write-Log -Message "Updating $Module from [$currentVersion] to [$latestVersion] to all users" -LogFileName $LogFileName -Severity Warning
                        Update-Module -Name $Module -RequiredVersion $latestVersion -Force
                    }
                }
                else {
                    Write-Log -Message "Importing module $Module" -LogFileName $LogFileName -Severity Information
                    Import-Module -Name $Module -Force
                }
            }
            else {
                Write-Log -Message "Importing module $Module" -LogFileName $LogFileName -Severity Information
                Import-Module -Name $Module -Force
            }
        }
        # Install-Module will obtain the module from the gallery and install it on your local machine, making it available for use.
        # Import-Module will bring the module and its functions into your current powershell session, if the module is installed.  
    }
    catch {
        Write-Log -Message "An error occurred in Get-RequiredModules() method - $($_)" -LogFileName $LogFileName -Severity Error        
    }
}

#endregion

#region MainFunctions
function Get-AllThreatIndicators {    
    $ThreatIndicatorsApi = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/$LogAnalyticsResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$LogAnalyticsWorkspaceName/providers/Microsoft.SecurityInsights/threatIntelligence/"
	$SECURITY_INSIGHTS_API_VERSION = "api-version=2022-07-01-preview"
    $PAGE_SIZE = "100"
    $Source = Collect-TISource
    $getAllIndicatorsWithSourceFilterUri = $ThreatIndicatorsApi + "query?$SECURITY_INSIGHTS_API_VERSION"
    $getAllIndicatorsPostParameters = @{ "pageSize" = $PAGE_SIZE; "sources" = @($Source) } | ConvertTo-Json    		
    
    # This flag checks whether the initial count of indicators in the workspace is already 0 or not
    $indicatorsFound = $false

    # Total count of indicators fetched for the customer's workspace ,and for the provided source
    $indicatorsFetched = 0

    # Total count of indicators deleted
    $indicatorsDeleted = 0

    # We have a max page size of 100 hence at a time, the fetch indicators call can only fetch a list of 100 indicators for any workspace. However, since a workspace can have more than
    # 100 indicators for a particular source, we need to perform the delete logic for 100 indicators repeatedly, until all indicators have been deleted.
    while ($true) {
    try {
        $response = Invoke-AzRestMethod -Uri $getAllIndicatorsWithSourceFilterUri -Method POST -Payload $getAllIndicatorsPostParameters
        if ($response -eq $null -or $response.StatusCode -ne 200) {            
            Write-Log -Message "Failed to fetch indicators. Status Code = $($response.StatusCode)" -LogFileName $LogFileName -Severity Information
            exit 1
        }
    
        $indicatorList = ($response.Content | ConvertFrom-Json).value
    }
    catch {        
        Write-Log -Message "Failed to get all indicators with the specified source. $($_.Exception)" -LogFileName $LogFileName -Severity Error    
        exit 1
    }
    
    if ($indicatorList.Count -eq 0) {
        # If the initial count of indicators in the customer's workspace is already 0, exit.
        if ($indicatorsFound -eq $false) {
            Write-Log -Message "No indicators found with source = $Source! Exiting ..." -LogFileName $LogFileName -Severity Error            
            break
        }
        else {
            Write-Log -Message "Finished querying workspace = $WorkspaceName for indicators with Source = $Source ..." -LogFileName $LogFileName -Severity Information
            Write-Log -Message "Fetched $indicatorsFetched indicators" -LogFileName $LogFileName -Severity Information
            Write-Log -Message "Deleted $indicatorsDeleted indicators" -LogFileName $LogFileName -Severity Information

            if ($indicatorsFetched -eq $indicatorsDeleted) {                
                Write-Log -Message "Successfully deleted all indicators in workspace = $WorkspaceName with Source = $Source" -LogFileName $LogFileName -Severity Information
            }
            else {                
                Write-Log -Message "Please re-run the script to delete remaining indicators or reach out to the script owners if you're facing any issues." -LogFileName $LogFileName -Severity Information
            }
            break
        }
    }

    $indicatorsFound = $true    
    Write-Log -Message "Successfully fetched $($indicatorList.Count) indicators for source = $Source. Deleting ..." -LogFileName $LogFileName -Severity Information
    
    $indicatorsFetched += $indicatorList.Count

    try {
        foreach ($indicator in $indicatorList) {
            $indicatorName = $($indicator).name
            Write-Host "Deleting indicator with ID: $indicatorName"
            Write-Log -Message "Deleting indicator with ID: $indicatorName" -LogFileName $LogFileName -Severity Information
            $deleteIndicatorUri = $ThreatIndicatorsApi + $indicator.name + "?$SECURITY_INSIGHTS_API_VERSION"
            $response = Invoke-AzRestMethod -Uri $deleteIndicatorUri -Method DELETE
            if ($response -eq $null -or $response.StatusCode -ne 200) {                
                Write-Log -Message "Failed to delete indicator $indicator.name. Status Code = $($response.StatusCode)" -LogFileName $LogFileName -Severity Information
                break
            }
            $indicatorsDeleted++
        }
    }
    catch {
        Write-Log -Message "Failed to delete indicator info: $($_.Exception)" -LogFileName $LogFileName -Severity Information        
    }
}
}

function Collect-TISource {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'TI:IoC'
    $form.Size = New-Object System.Drawing.Size(380,250)
    $form.StartPosition = 'CenterScreen'

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(90,130)
    $okButton.Size = New-Object System.Drawing.Size(75,30)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)
    $okButton.Enabled = $false    

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(170,130)
    $cancelButton.Size = New-Object System.Drawing.Size(75,30)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(350,60)
    $label.Text = "Enter valid TI Source"
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10,90)
    $textBox.Size = New-Object System.Drawing.Size(260,60)
    $textBox.TabIndex = 1
    $form.Controls.Add($textBox)  
    
    $textBox.Add_TextChanged({       
        
        if ($this.Text -match '[a-z]') {         
            $okButton.Enabled = $true
            $ErrorProvider.Clear()
        }
        else {
            $ErrorProvider.SetError($textBox, "Enter Valid TI Source")  
            $okButton.Enabled = $false            
        } 
    }) 

    $ErrorProvider = New-Object System.Windows.Forms.ErrorProvider
    $form.Add_Shown({$form.Activate()})
    $form.Add_Shown({$textBox.Select()})
    $form.Topmost = $true    
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $tiSource = $textBox.Text.Trim()        
        return $tiSource  
    }
    else {
        exit
    }
}

#endregion

#region 
# Check Powershell version, needs to be 5 or higher
if ($host.Version.Major -lt 5) {
    Write-Log "Supported PowerShell version for this script is 5 or above" -LogFileName $LogFileName -Severity Error    
    exit
}

$AzModulesQuestion = "Do you want to update required Az Modules to latest version?"
$AzModulesQuestionChoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$AzModulesQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$AzModulesQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

$AzModulesQuestionDecision = $Host.UI.PromptForChoice($title, $AzModulesQuestion, $AzModulesQuestionChoices, 1)

if ($AzModulesQuestionDecision -eq 0) {
    $UpdateAzModules = $true
}
else {
    $UpdateAzModules = $false
}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Get-RequiredModules("Az.Accounts")
Get-RequiredModules("Az.OperationalInsights")

$TimeStamp = Get-Date -Format yyyyMMdd_HHmmss 
$LogFileName = '{0}_{1}.csv' -f "Bulk_Delete_Threat_Indicators", $TimeStamp


#disconnect exiting connections and clearing contexts.
Write-Log "Clearing existing Azure connection" -LogFileName $LogFileName -Severity Information
    
$null = Disconnect-AzAccount -ContextName 'MyAzContext' -ErrorAction SilentlyContinue
    
Write-Log "Clearing existing Azure context `n" -LogFileName $LogFileName -Severity Information
    
get-azcontext -ListAvailable | ForEach-Object{$_ | remove-azcontext -Force -Verbose | Out-Null} #remove all connected content
    
Write-Log "Clearing of existing connection and context completed." -LogFileName $LogFileName -Severity Information
Try {
    #Connect to tenant with context name and save it to variable
    Connect-AzAccount -Tenant $TenantID -ContextName 'MyAzContext' -Force -ErrorAction Stop
        
    #Select subscription to build
    $GetSubscriptions = Get-AzSubscription -TenantId $TenantID | Where-Object {($_.state -eq 'enabled') } | Out-GridView -Title "Select Subscription to Use" -PassThru       
}
catch {    
    Write-Log "Error When trying to connect to tenant : $($_)" -LogFileName $LogFileName -Severity Error
    exit    
}

#loop through each selected subscription.. 
foreach($CurrentSubscription in $GetSubscriptions)
{
    Try 
    {
        #Set context for subscription being built
        $null = Set-AzContext -Subscription $CurrentSubscription.id
        $SubscriptionId = $CurrentSubscription.id
        Write-Log "Working in Subscription: $($CurrentSubscription.Name)" -LogFileName $LogFileName -Severity Information

        $LAWs = Get-AzOperationalInsightsWorkspace | Where-Object { $_.ProvisioningState -eq "Succeeded" } | Select-Object -Property Name, ResourceGroupName, Location | Out-GridView -Title "Select Log Analytics workspace" -PassThru 
        if($null -eq $LAWs) {
            Write-Log "No Log Analytics workspace found..." -LogFileName $LogFileName -Severity Error 
        }
        else {
            Write-Log "Listing Log Analytics workspace" -LogFileName $LogFileName -Severity Information
                        
            foreach($LAW in $LAWs) {                
                $LogAnalyticsWorkspaceName = $LAW.Name
                $LogAnalyticsResourceGroup = $LAW.ResourceGroupName                            
                
                $ThreatIndicators = Get-AllThreatIndicators                
            }                  

        } 	
    }
    catch [Exception]
    { 
        Write-Log $_ -LogFileName $LogFileName -Severity Error                         		
    }		 
}
#endregion DriverProgram 

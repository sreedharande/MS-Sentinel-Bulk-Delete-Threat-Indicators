<#       
  	THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SCRIPT OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

    .SYNOPSIS
        This PowerShell script deletes Threat Indicators from Sentinel Portal in bulk 
        

    .DESCRIPTION
        It performs the following actions:
            1. Gets all Threat Indicators
            2. Loop through each Threat Indicator and deletes Threat Indicator          
    
    .PARAMETER TenantId
        Enter Azure Tenant Id (required)  

    .NOTES
        AUTHOR: Sreedhar Ande
        LASTEDIT: 2/13/2022

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
    $ThreatIndicatorsApi = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/$LogAnalyticsResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$LogAnalyticsWorkspaceName/providers/Microsoft.SecurityInsights/threatIntelligence/main/indicators?api-version=2021-09-01-preview"
	    		
    try {        
        $ThreatIndicatorsResponse = Invoke-RestMethod -Uri $ThreatIndicatorsApi -Method "GET" -Headers $LaAPIHeaders -Verbose        			
        $ThreatIndicators = $ThreatIndicatorsResponse.value       

        while ($ThreatIndicatorsResponse.nextLink) {
            $IndicatorsNextLink = $ThreatIndicatorsResponse.nextLink
            $ThreatIndicatorsResponse = Invoke-RestMethod -Uri $IndicatorsNextLink -Method "GET" -Headers $LaAPIHeaders -UseBasicParsing -Verbose
            
            $ThreatIndicators += $ThreatIndicatorsResponse.value        
        }
        return $ThreatIndicators
    } 
    catch {                    
        Write-Log -Message "Get-AllThreatIndicators $($_)" -LogFileName $LogFileName -Severity Error		                
    }    
}

function Delete-ThreatIndicators {
    [CmdletBinding()]
    param (        
        [parameter(Mandatory = $true)] $AllThreatIndicators		
    )

    foreach($ThreatIndicator in $AllThreatIndicators) {   
        Write-Log "Deleting Threat Indicator $($ThreatIndicator.DisplayName)" -LogFileName $LogFileName -Severity Information
        $ThreatIndicatorsDeleteApi = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/$LogAnalyticsResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$LogAnalyticsWorkspaceName/providers/Microsoft.SecurityInsights/threatIntelligence/main/indicators/$($ThreatIndicator.Name)?api-version=2021-09-01-preview"
        try {        
            Invoke-RestMethod -Uri $ThreatIndicatorsDeleteApi -Method "DELETE" -Headers $LaAPIHeaders            
        } 
        catch {                    
            Write-Log -Message "Delete-ThreatIndicators $($_)" -LogFileName $LogFileName -Severity Error		                
        }
    }   
}

#endregion

#region DriverProgram
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

Get-RequiredModules("Az.Accounts")
Get-RequiredModules("Az.OperationalInsights")

$TimeStamp = Get-Date -Format yyyyMMdd_HHmmss 
$LogFileName = '{0}_{1}.csv' -f "Bulk_Delete_Threat_Indicators", $TimeStamp

# Check Powershell version, needs to be 5 or higher
if ($host.Version.Major -lt 5) {
    Write-Log "Supported PowerShell version for this script is 5 or above" -LogFileName $LogFileName -Severity Error    
    exit
}

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

$AzureAccessToken = (Get-AzAccessToken).Token            
$LaAPIHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$LaAPIHeaders.Add("Content-Type", "application/json")
$LaAPIHeaders.Add("Authorization", "Bearer $AzureAccessToken")

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
                Delete-ThreatIndicators -AllThreatIndicators $ThreatIndicators
            }                  

        } 	
    }
    catch [Exception]
    { 
        Write-Log $_ -LogFileName $LogFileName -Severity Error                         		
    }		 
}
#endregion DriverProgram 
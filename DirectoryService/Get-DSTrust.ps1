<#
.SYNOPSIS
    Retrieves trust relationships for domains or forests in Active Directory.
.DESCRIPTION
    Queries Active Directory to retrieve trust relationships either for all domains in the current 
    forest or for a specified forest. It supports querying the current domain context,a remote domain
    controller, or another forest using credentials. The trust type can be specified as either 'Domain' or 'Forest'.
.EXAMPLE
    PS C:\> Get-DSTrust
    Retrieves all domain trust relationships in the current forest context.
.EXAMPLE
    PS C:\> Get-DSTrust -ComputerName "DC01" -Credential (Get-Credential)
    Retrieves all domain trust relationships from a remote domain controller using provided credentials.
.EXAMPLE
    PS C:\> Get-DSTrust -ComputerName "DC01" -Credential (Get-Credential) -ForestName "otherforest.local" -TrustType "Forest"
    Retrieves forest-level trust relationships from a specified forest using credentials and a remote domain controller.
.OUTPUTS
    System.DirectoryServices.ActiveDirectory.TrustRelationshipInformation
#>
function Get-DSTrust {
    [CmdletBinding(DefaultParameterSetName = 'Current')]
    param(
        # Domain controller to connect to when not in a domain.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [string]
        $ComputerName,

        # Credentials to use for getting forest information.
        [Parameter(ParameterSetName = 'OtherForest',
                    Mandatory = $false)]
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        # Forest name.
        [Parameter(ParameterSetName = 'OtherForest',
                   Mandatory = $true)]
        [string]
        $ForestName,

        # Trust type (Forest or all Domains)
        [Parameter(Mandatory=$false)]
        [ValidateSet('Domain','Forest')]
        [String]
        $TrustType = 'Domain'
    )

    begin {
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Current' { 
                $forest = Get-DSForest
            }
            'Remote' { 
                $forest = Get-DSForest -ComputerName $ComputerName -Credential $Credential
            }
            'OtherForest' {
                $forest = Get-DSForest -ComputerName $ComputerName -Credential $Credential -ForestName $ForestName
            }
            Default {}
        }


        switch ($TrustType) {
            'Domain' { $forest.Domains | ForEach-Object {$_.GetAllTrustRelationships()} }
            'Forest' { $forest.GetAllTrustRelationships()}
            Default { }
        }		
    }

    end {}

}
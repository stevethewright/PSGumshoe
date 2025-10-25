<#
.SYNOPSIS
    Retrieves members of an Active Directory group, optionally using alternate or remote domain contexts.
.DESCRIPTION
    Retrieves the members of an Active Directory group. It supports querying the current domain context, 
    a remote domain controller or an alternate domain using credentials. Group membership is returned
    recursively by default.
.EXAMPLE
    PS C:\> Get-DSGroupMember -Identity "Domain Admins"
    Retrieves all members of the "Domain Admins" group from the current domain.
.EXAMPLE
    PS C:\> Get-DSGroupMember -ComputerName "DC01" -Credential (Get-Credential) -Identity "IT Support"
    Retrieves members of the "IT Support" group from a remote domain controller using provided credentials.
.EXAMPLE
    PS C:\> Get-DSGroupMember -Credential (Get-Credential) -Identity "FinanceGroup"
    Retrieves members of the "FinanceGroup" from an alternate domain context using credentials
.OUTPUTS
    System.DirectoryServices.AccountManagement.Principal
#>
function Get-DSGroupMember {
    [CmdletBinding(DefaultParameterSetName='Current')]
    param(
        # Domain controller.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [string]
        $ComputerName,
        
        # Credentials to use connection.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'Alternate',
                   Mandatory = $true)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory=$true)]
        $Identity
    )
    
    begin {
        $Recurse = $true
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        $sig = @"
[DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int NetGetJoinInformation(string server,out IntPtr domain,out int status);
"@
    }
    
    process {
        
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' {
                 $cArgs = @(
                    'DirectoryServer',
                    $ComputerName,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
                $typeName = 'DirectoryServices.ActiveDirectory.DirectoryContext'
                $context = New-Object $typeName  $cArgs
                $group=[System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context, $Identity)
            }

            'Alternate' {
                 $cArgs = @(
                    'Domain',
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
                $typeName = 'DirectoryServices.ActiveDirectory.DirectoryContext'
                $context = New-Object $typeName  $cArgs
                $group=[System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context, $Identity)
            }

            'Current' {
                $Context = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $group=[System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context, $Identity)
            }

            Default {}
        }

        $group.GetMembers($Recurse)
    }
    
    end {
    }
}
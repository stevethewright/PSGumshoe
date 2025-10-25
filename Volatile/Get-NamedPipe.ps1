<#
.SYNOPSIS
	Gets named pipes on the local computer.
.DESCRIPTION
	Provides a list of all named pipes currently available on the local system.
	It queries the `\\.\pipe\` namespace and returns each pipe as a custom object with a `NamedPipe` property.
	This can be useful for diagnostics, monitoring inter-process communication, or identifying suspicious activity.
.EXAMPLE
	PS C:\> Get-NamedPipe
	Lists all named pipes currently present on the local system.
#>
function Get-NamedPipe {
  [CmdletBinding()]
	[OutputType([PSObject])]
	param ()
	begin {
		$PipeList = @()
	}
	process{
		$Pipes = [IO.Directory]::GetFiles('\\.\pipe\')

		foreach ($Pipe in $Pipes) {
			$Object = New-Object -TypeName PSObject -Property (@{ 'NamedPipe' = $Pipe })
			$PipeList += $Object

		}
	}
	end {
		Write-Output -InputObject $PipeList
	}
}
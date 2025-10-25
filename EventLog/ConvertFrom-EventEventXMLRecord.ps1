<#
.SYNOPSIS
    Parses a raw EventLogRecord object into a structured PowerShell object using XML.
.DESCRIPTION
    Takes a System.Diagnostics.Eventing.Reader.EventLogRecord object, converts it to XML
    and extracts key fields from both the System and UserData sections. The result is returned
    as a custom PowerShell object with named properties for easier consumption and analysis.
.EXAMPLE
    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 | ConvertFrom-EventEventXMLRecord
    Parses the most recent Sysmon event into a structured object.
.INPUTS
    System.Diagnostics.Eventing.Reader.EventLogRecord
#>
function ConvertFrom-EventEventXMLRecord {
    [CmdletBinding()]
    param (
        # Event Log Record Object
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]
        $Event
    )
    begin {
        
    }

    process {
        [xml]$evtxml = $Event.toxml()
        $ProcInfo = [ordered]@{}
        $ProcInfo['EventId'] = $evtxml.Event.System.EventID
        $ProcInfo['Computer'] = $evtxml.Event.System.Computer
        $ProcInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
        $ProcInfo['TimeCreated'] = [datetime]$evtXml.Event.System.TimeCreated.SystemTime
        $evtxml.Event.UserData.EventXML.ChildNodes | ForEach-Object {
            $ProcInfo[$_.name] = $_.'#text'
        }
        $Obj = New-Object psobject -Property $ProcInfo
        $Obj
    }

    end {}
}
#################################
#FUNCTION 1: Dump-ADOuStructure
#################################

function Dump-ADOuStructure {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Dumps the OU hierarchy of a domain to an XML file.
    
    .DESCRIPTION
        Creates a date and time named XML backup of a domain's OU structure. Intended to be used with a sister
        function that can mirror the dumped OU structure to a test domain.

    .EXAMPLE
        Dump-ADOuStructure -Domain halo.net

        Dumps the OU hierarchy of the target domain, halo.net, to a date and time stamped XML file.

    .OUTPUTS
        Date and time stamped xml file, e.g. 150410093716_HALO_OU_Dump.xml

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE.

        This sample is not supported under any Microsoft standard support program or service. 
        The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
        implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance
        of the sample and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the script be liable for 
        any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of 
        the use of or inability to use the sample or documentation, even if Microsoft has been advised 
        of the possibility of such damages, rising out of the use of or inability to use the sample script, 
        even if Microsoft has been advised of the possibility of such damages. 
    #>
    ##########################################################################################################

    ###################################
    ## Function Options and Parameters
    ###################################

    #Requires -version 3
    #Requires -modules ActiveDirectory

    #Define and validate parameters
    [CmdletBinding()]
    Param(
          #The target domain
          [parameter(Mandatory,Position=1)]
          [ValidateScript({Get-ADDomain $_})] 
          [String]$Domain
          )


    #Set strict mode to identify typographical errors (uncomment whilst editing script)
    #Set-StrictMode -version Latest


    ##########################################################################################################

    ########
    ## Main
    ########

    #Craete a variable for the domain DN
    $DomainDn = (Get-ADDomain -Identity $Domain).DistinguishedName

    #Craete a variable for the domain DN
    $DomainNetbios = (Get-ADDomain -Identity $Domain).NetBIOSName

    #Specify a XML report variable
    $CsvReport = ".\$(Get-Date -Format yyMMddHHmmss)_$($DomainNetbios)_OU_Dump.xml" 

    #Create an array to  contain our custom PS objects
    $TotalOus = @()

    #Create user counter
    $i = 0

    #Get-ADOrganizationalUnit dumps the OU structure in a logical order (thank you cmdlet author!) 
    $Ous = Get-ADOrganizationalUnit -Filter * -SearchScope Subtree -Server $Domain -Properties ParentGuid -ErrorAction SilentlyContinue | 
           Select Name,DistinguishedName,ParentGuid 

    #Check that we have some output
    if ($Ous) {

        #Loop through each OU, create a custom object and add to $TotalOUs
        foreach ($Ou in $Ous){

            #Convert the parentGUID attribute (stored as a byte array) into a proper-job GUID
            $ParentGuid = ([GUID]$Ou.ParentGuid).Guid

            #Attempt to retrieve the object referenced by the parent GUID
            $ParentObject = Get-ADObject -Identity $ParentGuid -Server $Domain -ErrorAction SilentlyContinue

            #Check that we've retrieved the parent
            if ($ParentObject) {

                #Create a custom PS object
                $OuInfo = [PSCustomObject]@{

                    Name = $Ou.Name
                    DistinguishedName = $Ou.DistinguishedName
                    ParentDn = $ParentObject.DistinguishedName
                    DomainDn = $DomainDn
        
                 }   #End of $Properties...


                #Add the object to our array
                $TotalOus += $OuInfo

                #Spin up a progress bar for each filter processed
                Write-Progress -Activity "Finding OUs in $DomainDn" -Status "Processed: $i" -PercentComplete -1

                #Increment the filter counter
                $i++

            }   #End of if ($ParentObject)

        }   #End of foreach ($Ou in $Ous)


        #Dump custom OU info to XML file
        Export-Clixml -Path $CsvReport -InputObject $TotalOus

        #Message to screen
        Write-Host "OU information dumped to $CSVReport" 


    }   #End of if ($Ous)
    Else {

        #Write message to screen
        Write-Error -Message "Failed to retrieve OU information."


    }   #End of else ($Ous)

}   #end of function Dump-ADOuStructure


###################################
#FUNCTION 2: Mirror-ADOuStructure
###################################

function Mirror-ADOuStructure {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Mirrors an XML dump of a source domain's OU hierarchy to a target test domain.
    
    .DESCRIPTION
        Creates the OU structure contained in a backup XML file in a target domain. Does not create OUs if 
        they already exist.  
    
        Intended to be used with a sister function that dumps the OU structure from a source domain.

        Logs all function actions to a date and time named log.

        Requirements:

            * PowerShell ActiveDirectory Module
            * An XML backup created by partner Dump-ADOuStructure function
            * Trace32.exe (SMS Trace) or CMTrace.exe (Configuration Manager Trace Log Tool) to view script log

        NB - there will be an error written to screen following the test for the existence of an OU. This may 
             result in a lot of red text.

    .EXAMPLE
        Mirror-ADOuStructure -Domain contoso.com -BackupXml .\150410093716_HALO_OU_Dump.xml

        Creates the OU structure contained in the 150410093716_HALO_OU_Dump.xml backup file in the contoso.com
        domain. Does not create OUs if they already exist. 

        Writes a log file of all function actions.

    .OUTPUTS
        Date and time stamped log file, e.g. 150410110533_AD_OU_Mirror.log, for use with Trace32.exe (SMS Trace) 
        or CMTrace.exe (Configuration Manager Trace Log Tool)

        SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
        CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\


        EXIT CODES:  1 - Report file not found
                     2 - Custom XML OU file not found

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE.

        This sample is not supported under any Microsoft standard support program or service. 
        The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
        implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance
        of the sample and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the script be liable for 
        any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of 
        the use of or inability to use the sample or documentation, even if Microsoft has been advised 
        of the possibility of such damages, rising out of the use of or inability to use the sample script, 
        even if Microsoft has been advised of the possibility of such damages. 
    #>
    ##########################################################################################################

    ###################################
    ## Function Options and Parameters
    ###################################

    #Requires -version 3
    #Requires -modules ActiveDirectory


    #Define and validate parameters
    [CmdletBinding()]
    Param(
          #The target domain
          [parameter(Mandatory=$True,Position=1)]
          [ValidateScript({Get-ADDomain -Identity $_})] 
          [String]$Domain,

          #The source backup file 
          [parameter(Mandatory=$True,Position=2)]
          [ValidateScript({Test-Path -Path $_})]
          [String]$BackupXml
          )


    #Set strict mode to identify typographical errors (uncomment whilst editing script)
    #Set-StrictMode -version Latest



    ##########################################################################################################

    ##############################
    ## FUNCTION - Log-ScriptEvent
    ##############################

    <#
       Write a line of data to a script log file in a format that can be parsed by Trace32.exe / CMTrace.exe

       The severity of the logged line can be set as:

            1 - Information
            2 - Warning
            3 - Error

       Warnings will be highlighted in yellow. Errors are highlighted in red.

       The tools:

       SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
       CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\
    #>

    Function Log-ScriptEvent {

        #Define and validate parameters
        [CmdletBinding()]
        Param(
              #Path to the log file
              [parameter(Mandatory=$True)]
              [String]$NewLog,

              #The information to log
              [parameter(Mandatory=$True)]
              [String]$Value,

              #The source of the error
              [parameter(Mandatory=$True)]
              [String]$Component,

              #The severity (1 - Information, 2- Warning, 3 - Error)
              [parameter(Mandatory=$True)]
              [ValidateRange(1,3)]
              [Single]$Severity
              )


        #Obtain UTC offset
        $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime 
        $DateTime.SetVarDate($(Get-Date))
        $UtcValue = $DateTime.Value
        $UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)


        #Create the line to be logged
        $LogLine =  "<![LOG[$Value]LOG]!>" +`
                    "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
                    "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
                    "component=`"$Component`" " +` 
                    "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
                    "type=`"$Severity`" " +`
                    "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
                    "file=`"`">"

        #Write the line to the passed log file
        Add-Content -Path $NewLog -Value $LogLine

    }   #End of Function Log-ScriptEvent


    ##########################################################################################################

    ########
    ## Main
    ########

    #Create a variable to represent a new script log, constructing the report name from date details
    $NewReport = ".\$(Get-Date -Format yyMMddHHmmss)_AD_OU_Mirror.log" 

    #Make sure the script log has been created
    if (New-Item -ItemType File -Path $NewReport) {

        ##Start writing to the script log (Start_Script)
        Log-ScriptEvent $NewReport ("=" * 90) "Start-Script" 1
        Log-ScriptEvent $NewReport "TARGET_DOMAIN: $Domain" "Start_Script" 1
        Log-ScriptEvent $NewReport "BACKUP_SOURCE: $BackupXml" "Start_Script" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Start_Script" 1
        Log-ScriptEvent $NewReport " " " " 1

        #Instantiate an object for the target domain
        $TargetDomain = Get-ADDomain -Identity $Domain

        #Obtain the target domain FQDN
        $TargetDomainFqdn = $TargetDomain.DNSRoot

        #Obtain the target domain DN
        $TargetDomainDn = $TargetDomain.DistinguishedName

        #Obtain the target domain PDCe
        $TargetPdc = $TargetDomain.PDCEmulator

        #Import the OU information contained in the XML file
        $OuInfo = Import-Clixml -Path $BackupXml -ErrorAction SilentlyContinue

        #Make sure we have custom OU info
        if ($OuInfo) {

            #Log custom XML import success
            Log-ScriptEvent $NewReport "Custom OU objects successfully imported from $BackupXml" "Import_OUs" 1
            Log-ScriptEvent $NewReport " " " " 1 

            #Obtain the source domain DN from the first custom OU object
            $SourceDomainDn = ($OuInfo | Select -First 1).DomainDn

            #Create a counter
            $i = 0

            #Loop through each of the OUs
            foreach ($Ou in $OuInfo) {

                #Replace the domain DN with the target filter DN for our OU
                $TargetOuDn = $Ou.DistinguishedName –Replace $SourceDomainDn,$TargetDomainDn

                #Replace the domain DN with the target filter DN for our parent path
                $TargetParentDn = $Ou.ParentDn –Replace $SourceDomainDn,$TargetDomainDn

                #Test that the parent exists
                Try {$TargetParent = Get-ADObject -Identity $TargetParentDn -Server $TargetPdc}
                Catch{}

                #Check to see that the parent OU already exists
                if ($TargetParent) {

                    #Log that object exists
                    Log-ScriptEvent $NewReport "`"$TargetParentDn`" parent already exists in $Domain - checking for child OU..." "Import_OUs" 1

                    #Test that the OU doesn't already exist
                    Try {$TargetOu= Get-ADObject -Identity $TargetOuDn -Server $TargetPdc}
                    Catch {}

                    #Check to see if the target OU already exists
                    if ($TargetOu) {

                        #Log that object exists
                        Log-ScriptEvent $NewReport "`"$TargetOuDn`" already exists in $Domain" "Import_OUs" 1
                        Log-ScriptEvent $NewReport " " " " 1 

                    }   #End of if ($TargetOu)

                    else {

                        #Log that object does not exist
                        Log-ScriptEvent $NewReport "`"$TargetOuDn`" does not exist in $Domain - attempting to create OU..." "Import_OUs" 1


                        #Create the OU
                        $NewOu = New-ADOrganizationalUnit -Name $Ou.Name `                                                          -Path $TargetParentDn `                                                          -Server $TargetPdc `                                                          -ErrorAction SilentlyContinue

                            #Check the success of the New-ADOrganizationalUnit cmdlet
                            if ($?) {

                                #Log success of New-ADOrganizationalUnit cmdlet
                                Log-ScriptEvent $NewReport "Creation of `"$TargetOuDn`" succeeded." "Import_OUs" 1
                                Log-ScriptEvent $NewReport " " " " 1    


                            }   #End of if ($?)

                            else {

                                #Log failure of New-ADOrganizationalUnit cmdlet
                                Log-ScriptEvent $NewReport "Creation of `"$TargetOuDn`" failed. $($Error[0].exception.message)" "Import_OUs" 3
                                Log-ScriptEvent $NewReport " " " " 1    


                            }   #End of else ($?)


                    }   #End of else ($TargetOu)


                }   #End of if ($TargetParent)
                else {

                    #Log that object doesn't exist
                    Log-ScriptEvent $NewReport "$TargetParentDn parent does not exist in $Domain" "Import_OUs" 3

                }   #End of else ($TargetParent)


                #Spin up a progress bar for each filter processed
                Write-Progress -Activity "Importing OUs to $TargetDomainFqdn" -Status "Processed: $i" -PercentComplete -1

                #Increment the filter counter
                $i++

                #Nullify key variables
                $TargetOu = $null
                $TargetParent = $null


            }   #End of foreach($Ou in $Ous)

        }   #End of if ($OuInfo)

        else {

        #Log failure to import custom OU XML object
        Log-ScriptEvent $NewReport "$BackupXml import failed" "Import_OUs" 3
        Log-ScriptEvent $NewReport "Script execution stopped" "Import_OUs" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Import_OUs" 1
        Write-Error "$BackupXml not found. Script execution stopped."
        Exit 2

        }   #End of else ($OuInfo)


        #Close of the script log
        Log-ScriptEvent $NewReport " " " " 1 
        Log-ScriptEvent $NewReport ("=" * 90) "Finish_Script" 1
        Log-ScriptEvent $NewReport "OUs_PROCESSED: $i" "Finish_Script" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Finish_Script" 1


    }   #End of if (New-Item -ItemType File -Path $NewReport)

    else {

        #Write a custom error
        Write-Error "$NewReport not found. Function execution stopped."
        Exit 1

    }   #End of else (New-Item -ItemType File -Path $NewReport)


}   #end of function Mirror-ADOuStructure



###########################
#FUNCTION 3: Dump-ADUsers
###########################

function Dump-ADUsers {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Dumps Users accounts for a domain
    
    .DESCRIPTION
        Creates a date and time named XML backup of a domain's user accounts. Intended to be used with a sister
        function that can mirror the dumped OU structure to a test domain.

    .EXAMPLE
        Dump-ADUsers -Domain halo.net

        Dumps the user accounts of the target domain, halo.net, to a date and time stamped XML file.

    .EXAMPLE
        Dump-ADUsers -Domain halo.net -TargetOu "OU=Test Users,DC=halo,DC=net"

        Dumps the user accounts of the target OU, "Test Users", and subtree to a date and time stamped
        XML file.

    .OUTPUTS
        Date and time stamped xml file, e.g. 150410093716_HALO_User_Dump.xml

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE.

        This sample is not supported under any Microsoft standard support program or service. 
        The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
        implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance
        of the sample and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the script be liable for 
        any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of 
        the use of or inability to use the sample or documentation, even if Microsoft has been advised 
        of the possibility of such damages, rising out of the use of or inability to use the sample script, 
        even if Microsoft has been advised of the possibility of such damages. 
    #>
    ##########################################################################################################

    #################################
    ## Function Options and Parameters
    #################################

    #Requires -version 3
    #Requires -modules ActiveDirectory

    #Define and validate parameters
    [CmdletBinding()]
    Param(
          #The target domain
          [parameter(Mandatory,Position=1)]
          [ValidateScript({Get-ADDomain -Identity $_})] 
          [String]$Domain,

          #Optional target OU 
          [parameter(Position=2)]
          [ValidateScript({Get-ADOrganizationalUnit -Identity $_})]
          [String]$TargetOu
          )


    #Set strict mode to identify typographical errors (uncomment whilst editing script)
    #Set-StrictMode -version Latest


    ##########################################################################################################

    ########
    ## Main
    ########

    #Create a variable for the domain DN
    $DomainDn = (Get-ADDomain -Identity $Domain).DistinguishedName

    #Create a variable for the domain DN
    $DomainNetbios = (Get-ADDomain -Identity $Domain).NetBIOSName

    #Specify a XML report variable
    $XmlReport = ".\$(Get-Date -Format yyMMddHHmmss)_$($DomainNetbios)_User_Dump.xml" 

    #Create an array to  contain our custom PS objects
    $TotalUsers = @()

    #Create user counter
    $i = 0

    #Check for target OU
    if ($TargetOu) {

        #Create splatted parameters for Get-ADuser command
        $Parameters = @{

            Filter = "*"
            SearchBase = $TargetOu
            SearchScope = "SubTree"
            Server = $Domain
            ErrorAction = "SilentlyContinue"

        }   #End of $Parameters

    }   #End of if ($TargetOu)
    else {

        #Create splatted parameters for Get-ADuser command
        $Parameters = @{

            Filter = "*"
            SearchScope = "SubTree"
            Server = $Domain
            ErrorAction = "SilentlyContinue"

        }   #End of $Parameters

    }   #end of else ($TargetOu)

    #Get a list of AD users
    $Users = Get-ADUser @Parameters -Properties mail,ParentGuid,Description,DisplayName

    if ($Users) {

        foreach ($User in $Users) {

            #Convert the parentGUID attribute (stored as a byte array) into a proper-job GUID
            $ParentGuid = ([GUID]$User.ParentGuid).Guid

            #Attempt to retrieve the object referenced by the parent GUID
            $ParentObject = Get-ADObject -Identity $ParentGuid -Server $Domain -ErrorAction SilentlyContinue

            #Check that we've retrieved the parent
            if ($ParentObject) {

                #Create a custom PS object
                $UserInfo = [PSCustomObject]@{

                    GivenName = $User.GivenName
                    Surname = $User.Surname
                    Name = $User.Name
                    SamAccountName = $User.SamAccountName
                    DisplayName = $User.DisplayName
                    mail = $User.mail
                    Description = $User.Description
                    UserDn = $User.DistinguishedName 
                    ParentDn = $ParentObject.DistinguishedName
                    DomainDn = $DomainDn
    
                 }   #End of $UserInfo...


                #Add the object to our array
                $TotalUsers += $UserInfo

                #Spin up a progress bar for each filter processed
                Write-Progress -Activity "Finding users in $DomainDn" -Status "Processed: $i" -PercentComplete -1

                #Increment the filter counter
                $i++

            }   #end of if ($ParentObject)

        }   #end of foreach ($User in $Users)

    }   #end if ($Users)


    #Dump custom User info to XML file
    Export-Clixml -Path $XmlReport -InputObject $TotalUsers

    #Message to screen
    Write-Host "User information dumped to $XmlReport" 


}   #end of function Dump-ADUsers



#############################
#FUNCTION 4: Mirror-ADUsers
#############################

function Mirror-ADUsers {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Mirrors an XML dump of a source domain's user accounts to a target test domain.
    
    .DESCRIPTION
        Creates user accounts contained in a backup XML file in a target domain. Does not create users if 
        they already exist. Does not create users if the parent OU does not already exist.  
    
        Intended to be used with a sister function that dumps the user accounts from a source domain.

        Logs all function actions to a date and time named log.

        Requirements:

            * PowerShell ActiveDirectory Module
            * An XML backup created by partner Dump-ADUsers function
            * Trace32.exe (SMS Trace) or CMTrace.exe (Configuration Manager Trace Log Tool) to view script log

    .EXAMPLE
        Mirror-ADUsers -Domain contoso.com -BackupXml .\150410093716_HALO_User_Dump.xml

        Creates the user accounts contained in the 150410093716_HALO_User_Dump.xml backup file in the contoso.com
        domain. Does not create users if they already exist. Does not create users if the parent OU does not
        already exist.  

        Writes a log file of all function actions.

    .EXAMPLE
        Mirror-ADUsers -Domain contoso.com 
                       -BackupXml .\150410093716_HALO_User_Dump.xml
                       -TargetOu "OU=Test Users,DC=Halo,DC=Net"

        Creates the user accounts contained in the 150410093716_HALO_OU_Dump.xml backup file in the contoso.com
        domain. Creates Users in the 'Test Users' OU. Does not create users if they already exist. Does not 
        create users if the target OU does not exist.

        Writes a log file of all functions actions.

    .OUTPUTS
        Date and time stamped log file, e.g. 150410110533_AD_User_Mirror.log, for use with Trace32.exe (SMS Trace) 
        or CMTrace.exe (Configuration Manager Trace Log Tool)

        SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
        CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\


        EXIT CODES:  1 - Report file not found
                     2 - Custom XML User file not found

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE.

        This sample is not supported under any Microsoft standard support program or service. 
        The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
        implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance
        of the sample and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the script be liable for 
        any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of 
        the use of or inability to use the sample or documentation, even if Microsoft has been advised 
        of the possibility of such damages, rising out of the use of or inability to use the sample script, 
        even if Microsoft has been advised of the possibility of such damages. 
    #>
    ##########################################################################################################

    #################################
    ## Function Options and Parameters
    #################################

    #Requires -version 3
    #Requires -modules ActiveDirectory


    #Define and validate parameters
    [CmdletBinding()]
    Param(
          #The target domain
          [parameter(Mandatory=$True,Position=1)]
          [ValidateScript({Get-ADDomain -Identity $_})] 
          [String]$Domain,

          #The source backup file 
          [parameter(Mandatory=$True,Position=2)]
          [ValidateScript({Test-Path -Path $_})]
          [String]$BackupXml,

          #Optional target OU 
          [parameter(Position=3)]
          [ValidateScript({Get-ADOrganizationalUnit -Identity $_})]
          [String]$TargetOu
          )


    #Set strict mode to identify typographical errors (uncomment whilst editing script)
    #Set-StrictMode -version Latest



    ##########################################################################################################

    ##############################
    ## FUNCTION - Log-ScriptEvent
    ##############################

    <#
       Write a line of data to a script log file in a format that can be parsed by Trace32.exe / CMTrace.exe

       The severity of the logged line can be set as:

            1 - Information
            2 - Warning
            3 - Error

       Warnings will be highlighted in yellow. Errors are highlighted in red.

       The tools:

       SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
       CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\
    #>

    Function Log-ScriptEvent {

        #Define and validate parameters
        [CmdletBinding()]
        Param(
              #Path to the log file
              [parameter(Mandatory=$True)]
              [String]$NewLog,

              #The information to log
              [parameter(Mandatory=$True)]
              [String]$Value,

              #The source of the error
              [parameter(Mandatory=$True)]
              [String]$Component,

              #The severity (1 - Information, 2- Warning, 3 - Error)
              [parameter(Mandatory=$True)]
              [ValidateRange(1,3)]
              [Single]$Severity
              )


        #Obtain UTC offset
        $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime 
        $DateTime.SetVarDate($(Get-Date))
        $UtcValue = $DateTime.Value
        $UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)


        #Create the line to be logged
        $LogLine =  "<![LOG[$Value]LOG]!>" +`
                    "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
                    "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
                    "component=`"$Component`" " +` 
                    "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
                    "type=`"$Severity`" " +`
                    "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
                    "file=`"`">"

        #Write the line to the passed log file
        Add-Content -Path $NewLog -Value $LogLine

    }   #End of Function Log-ScriptEvent


    ##########################################################################################################

    ########
    ## Main
    ########

    #Create a variable to represent a new script log, constructing the report name from date details
    $NewReport = ".\$(Get-Date -Format yyMMddHHmmss)_AD_User_Mirror.log" 

    #Make sure the script log has been created
    if (New-Item -ItemType File -Path $NewReport) {

        ##Start writing to the script log (Start_Script)
        Log-ScriptEvent $NewReport ("=" * 90) "Start-Script" 1
        Log-ScriptEvent $NewReport "TARGET_DOMAIN: $Domain" "Start_Script" 1
        Log-ScriptEvent $NewReport "BACKUP_SOURCE: $BackupXml" "Start_Script" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Start_Script" 1
        Log-ScriptEvent $NewReport " " " " 1

        #Instantiate an object for the target domain
        $TargetDomain = Get-ADDomain -Identity $Domain

        #Obtain the target domain FQDN
        $TargetDomainFqdn = $TargetDomain.DNSRoot

        #Obtain the target domain DN
        $TargetDomainDn = $TargetDomain.DistinguishedName

        #Import the OU information contained in the XML file
        $UserInfo= Import-Clixml -Path $BackupXml -ErrorAction SilentlyContinue

        #Make sure we have custom user info
        if ($UserInfo) {

            #Log custom XML import success
            Log-ScriptEvent $NewReport "Custom User objects successfully imported from $BackupXml" "Mirror_Users" 1
            Log-ScriptEvent $NewReport " " " " 1 

            #Obtain the source domain DN from the first custom user object
            $SourceDomainDn = ($UserInfo| Select -First 1).DomainDn

            #Create counters
            $i = 0    # users processed
            $j = 0    # users matched
            $k = 0    # user created
            $l = 0    # BUILTIN matched
            $m = 0    # user creation failed

            #Loop through each of the custom user objects
            foreach ($User in $UserInfo) {
            
                #Check for know accounts
                Switch -Wildcard ($User.SamAccountName) {

                    "Administrator" {

                        #Log that BUILTIN account found
                        Log-ScriptEvent $NewReport "`"$(($User).SamAccountName)`" BUILTIN Administrator account matched in $Domain" "Mirror_Users" 1
                        Log-ScriptEvent $NewReport " " " " 1 

                        #Increment user processed and BUILTIN matched counters
                        $i++
                        $l++

                    }

                    "Guest" {

                        #Log that BUILTIN account found
                        Log-ScriptEvent $NewReport "`"$(($User).SamAccountName)`" BUILTIN Guest account matched in $Domain" "Mirror_Users" 1
                        Log-ScriptEvent $NewReport " " " " 1 

                        #Increment user processed and BUILTIN matched counters
                        $i++
                        $l++
                    }

                    "krbtgt*" {

                        #Log that BUILTIN account found
                        Log-ScriptEvent $NewReport "`"$(($User).SamAccountName)`" BUILTIN krbtgt account matched in $Domain" "Mirror_Users" 1
                        Log-ScriptEvent $NewReport " " " " 1 

                        #Increment user processed and BUILTIN matched counters
                        $i++
                        $l++
                    }

                    "*$" {

                        #Log that BUILTIN account found
                        Log-ScriptEvent $NewReport "`"$(($User).SamAccountName)`" BUILTIN TDO account matched in $Domain" "Mirror_Users" 1
                        Log-ScriptEvent $NewReport " " " " 1 

                        #Increment user processed and BUILTIN matched counters
                        $i++
                        $l++
                    }

                    Default {

                        #Test that the user SamAccountName doesn't already exist
                        try {$TargetUserSAM = Get-ADUser -Identity $User.SamAccountName -Server $TargetDomainFqdn}
                        catch {}

                        #If we have a user then onwards...
                        if ($TargetUserSAM) {

                            #Log that object exists
                            Log-ScriptEvent $NewReport "SamAccountName - `"$(($User).SamAccountName)`" - already exists in $Domain" "Mirror_Users" 1
                            Log-ScriptEvent $NewReport " " " " 1 
                
                            #Increment user matched counter
                            $j++

                        }   #End of if ($TargetUserSAM)

                        else {

                            #Log that object does not exist
                            Log-ScriptEvent $NewReport "SamAccountName - `"$(($User).SamAccountName)`" - does not exist in $Domain" "Mirror_Users" 1

                            #Test that the user Name doesn't already exist
                            try{$TargetUserName = Get-ADUser -Identity $User.Name -Server $TargetDomainFqdn}
                            catch {}

                            #If we have a user then onwards...
                            if ($TargetUserName) {

                                #Log that object exists
                                Log-ScriptEvent $NewReport "User Name - `"$(($User).Name)`" - already exists in $Domain" "Mirror_Users" 1
                                Log-ScriptEvent $NewReport " " " " 1 
                
                                #Increment user matched counter
                                $j++

                            }   #End of if ($TargetUserName)

                            else {

                                #Log that object does not exist
                                Log-ScriptEvent $NewReport "User Name - `"$(($User).Name)`" - does not exist in $Domain" "Mirror_Users" 1

                                #Determine where we create the user
                                if ($TargetOu) {

                                    #Log that we are using a parameter value as our target OU
                                    Log-ScriptEvent $NewReport "Using supplied paramter - $TargetOu - as user parent OU" "Mirror_Users" 1  
                            
                                    #Attempt to create user in Target OU
                                    $NewUser = New-ADUser -Name $User.Name `                                                          -GivenName $User.GivenName `                                                          -Surname $User.SurName `                                                          -SamAccountName $User.SamAccountName `                                                          -DisplayName $User.DisplayName `                                                          -EmailAddress $User.Mail `                                                          -Description $User.Description `                                                          -Path $TargetOu `                                                          -ErrorAction SilentlyContinue

                                    #Check the success of the New-ADUser cmdlet
                                    if ($?) {

                                        #Log success of New-ADUser cmdlet
                                        Log-ScriptEvent $NewReport "Creation of `"$(($User).SamAccountName)`" succeeded." "Mirror_Users" 1
                                        Log-ScriptEvent $NewReport " " " " 1 
                                    
                                        #Increment user created counter
                                        $k++


                                    }   #End of if ($?)

                                    else {

                                        #Log failure of New-ADUser cmdlet
                                        Log-ScriptEvent $NewReport "Creation of `"$(($User).SamAccountName)`" failed. $($Error[0].exception.message)" "Mirror_Users" 3
                                        Log-ScriptEvent $NewReport " " " " 1    

                                        #Increment user creation failed counter
                                        $m++


                                    }   #End of else ($?)                      


                            }   #End of if ($TargetOu)
                                else {

                                    #Replace the domain DN with the target filter DN for our parent path
                                    $TargetParentDn = $User.ParentDn –Replace $SourceDomainDn,$TargetDomainDn

                                    #Test that the parent exists
                                    Try{$TargetParent = Get-ADObject -Identity $TargetParentDn -Server $TargetDomainFqdn}
                                    Catch {}

                                    #Check to see that the parent OU already exists
                                    if ($TargetParent) {

                                        #Log that object exists
                                        Log-ScriptEvent $NewReport "`"$TargetParentDn`" parent already exists in $Domain" "Mirror_Users" 1

                                        #Attempt to create user in Parent OU
                                        $NewUser = New-ADUser -Name $User.Name `                                                              -GivenName $User.GivenName `                                                              -Surname $User.SurName `                                                              -SamAccountName $User.SamAccountName `                                                              -DisplayName $User.DisplayName `                                                              -EmailAddress $User.Mail `                                                              -Description $User.Description `                                                              -Path $TargetParentDn `                                                              -ErrorAction SilentlyContinue

                                            #Check the success of the New-ADUser cmdlet
                                            if ($?) {

                                                #Log success of New-ADUser cmdlet
                                                Log-ScriptEvent $NewReport "Creation of `"$(($User).SamAccountName)`" succeeded." "Mirror_Users" 1
                                                Log-ScriptEvent $NewReport " " " " 1 
                                        
                                                #Increment user created counter
                                                $k++


                                            }   #End of if ($?)

                                            else {

                                                #Log failure of New-ADUser cmdlet
                                                Log-ScriptEvent $NewReport "Creation of `"$(($User).SamAccountName)`" failed. $($Error[0].exception.message)" "Mirror_Users" 3
                                                Log-ScriptEvent $NewReport " " " " 1    

                                                #Increment user creation failed counter
                                                $m++


                                            }   #End of else ($?) 

                                    }   #End of if ($TargetParent)
                                    else {

                                        #Log that object does not exist 
                                        Log-ScriptEvent $NewReport "`"$TargetParentDn`" parent does not exist in $Domain... user creation will not be attempted" "Mirror_Users" 1
                                        Log-ScriptEvent $NewReport " " " " 1 

                                    }   #End of else ($TargetParent)

                                }   #End of else ($TargetOu)

                            }   #End of else ($TargetUserName)

                        }   #End of else ($TargetUserSAM)


                        #Spin up a progress bar for each filter processed
                        Write-Progress -Activity "Mirroring users to $TargetDomainFqdn" -Status "Processed: $i" -PercentComplete -1

                        #Increment the user processed counter
                        $i++

                        #Nullify key variables
                        $TargetUserSAM = $null
                        $TargetUserName = $null
                        $TargetUserDn = $null
                        $TargetParent = $null

                    }   #End of Switch Default

                }   #End of Switch -Wildcard ($User.UserDn)

            }   #End of foreach($User in $Users)

        }   #End of if ($UserInfo)

        else {

        #Log failure to import custom OU XML object
        Log-ScriptEvent $NewReport "$BackupXml import failed" "Mirror_Users" 3
        Log-ScriptEvent $NewReport "Script execution stopped" "Mirror_Users" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Mirror_Users" 1
        Write-Error "$BackupXml not found. Script execution stopped."
        Exit 2

        }   #End of else ($UserInfo)


        #Close of the script log
        Log-ScriptEvent $NewReport " " " " 1 
        Log-ScriptEvent $NewReport ("=" * 90) "Finish_Script" 1
        Log-ScriptEvent $NewReport "USERS_PROCESSED: $i" "Finish_Script" 1
        Log-ScriptEvent $NewReport "ACCOUNTS_MATCHED: $j" "Finish_Script" 1
        Log-ScriptEvent $NewReport "ACCOUNTS_CREATED_SUCCESS: $k" "Finish_Script" 1
        Log-ScriptEvent $NewReport "ACCOUNTS_CREATED_FAILURE: $m" "Finish_Script" 1
        Log-ScriptEvent $NewReport "BUILTIN_ACCOUNTS: $l" "Finish_Script" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Finish_Script" 1


    }   #End of if (New-Item -ItemType File -Path $NewReport)

    else {

        #Write a custom error
        Write-Error "$NewReport not found. Script execution stopped."
        Exit 1

    }   #End of else (New-Item -ItemType File -Path $NewReport)

}   #end of function Mirror-ADUsers



############################
#FUNCTION 5: Dump-ADGroups
############################

function Dump-ADGroups {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Dumps groups for a domain
    
    .DESCRIPTION
        Creates a date and time named XML backup of a domain's groups. Intended to be used with a sister
        script that can mirror the dumped groups to a test domain.

    .EXAMPLE
        Dump-ADGroups -Domain halo.net

        Dumps the groups of the target domain, halo.net, to a date and time stamped XML file.

    .EXAMPLE
        Dump-ADGroups -Domain halo.net -TargetOu "OU=Test Groups,DC=halo,DC=net"

        Dumps the groups of the target OU, "Test Groups", and subtree to a date and time stamped
        XML file.

    .OUTPUTS
        Date and time stamped xml file, e.g. 150410093716_HALO_Group_Dump.xml

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE.

        This sample is not supported under any Microsoft standard support program or service. 
        The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
        implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance
        of the sample and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the script be liable for 
        any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of 
        the use of or inability to use the sample or documentation, even if Microsoft has been advised 
        of the possibility of such damages, rising out of the use of or inability to use the sample script, 
        even if Microsoft has been advised of the possibility of such damages. 
    #>
    ##########################################################################################################

    #################################
    ## Function Options and Parameters
    #################################

    #Requires -version 3
    #Requires -modules ActiveDirectory

    #Define and validate parameters
    [CmdletBinding()]
    Param(
          #The target domain
          [parameter(Mandatory,Position=1)]
          [ValidateScript({Get-ADDomain -Identity $_})] 
          [String]$Domain,

          #Optional target OU 
          [parameter(Position=2)]
          [ValidateScript({Get-ADOrganizationalUnit -Identity $_})]
          [String]$TargetOu
          )


    #Set strict mode to identify typographical errors (uncomment whilst editing script)
    #Set-StrictMode -version Latest


    ##########################################################################################################

    ########
    ## Main
    ########

    #Create a variable for the domain DN
    $DomainDn = (Get-ADDomain -Identity $Domain).DistinguishedName

    #Create a variable for the domain DN
    $DomainNetbios = (Get-ADDomain -Identity $Domain).NetBIOSName

    #Specify a XML report variable
    $XmlReport = ".\$(Get-Date -Format yyMMddHHmmss)_$($DomainNetbios)_Group_Dump.xml" 

    #Create an array to  contain our custom PS objects
    $TotalGroups = @()

    #Create user counter
    $i = 0

    #Check for target OU
    if ($TargetOu) {

        #Create splatted parameters for Get-ADuser command
        $Parameters = @{

            Filter = "*"
            SearchBase = $TargetOu
            SearchScope = "SubTree"
            Server = $Domain
            ErrorAction = "SilentlyContinue"

        }   #End of $Parameters

    }   #End of if ($TargetOu)
    else {

        #Create splatted parameters for Get-ADuser command
        $Parameters = @{

            Filter = "*"
            SearchScope = "SubTree"
            Server = $Domain
            ErrorAction = "SilentlyContinue"

        }   #End of $Parameters

    }   #end of else ($TargetOu)

    #Get a list of AD users
    $Groups = Get-ADGroup @Parameters -Properties mail,ParentGuid,Description,DisplayName,members,managedBy

    if ($Groups) {

        foreach ($Group in $Groups) {

            #Convert the parentGUID attribute (stored as a byte array) into a proper-job GUID
            $ParentGuid = ([GUID]$Group.ParentGuid).Guid

            #Attempt to retrieve the object referenced by the parent GUID
            $ParentObject = Get-ADObject -Identity $ParentGuid -Server $Domain -ErrorAction SilentlyContinue

            #Check that we've retrieved the parent
            if ($ParentObject) {

                #Create a custom PS object
                $GroupInfo = [PSCustomObject]@{

                    GroupCategory = $Group.GroupCategory
                    GroupScope = $Group.GroupScope
                    Name = $Group.Name
                    SamAccountName = $Group.SamAccountName
                    DisplayName = $Group.DisplayName
                    members = $Group.members
                    managedBy = $Group.managedBy
                    Description = $Group.Description
                    GroupDn = $Group.DistinguishedName 
                    ParentDn = $ParentObject.DistinguishedName
                    DomainDn = $DomainDn
    
                 }   #End of $GroupInfo...


                #Add the object to our array
                $TotalGroups += $GroupInfo

                #Spin up a progress bar for each filter processed
                Write-Progress -Activity "Finding groups in $DomainDn" -Status "Processed: $i" -PercentComplete -1

                #Increment the filter counter
                $i++

            }   #end of if ($ParentObject)

        }   #end of foreach ($Group in $Groups)

    }   #end if ($Groups)


    #Dump custom User info to XML file
    Export-Clixml -Path $XmlReport -InputObject $TotalGroups

    #Message to screen
    Write-Host "User information dumped to $XmlReport" 


}   #end of function Dump-ADGroups



##############################
#FUNCTION 6: Mirror-ADGroups
##############################

function Mirror-ADGroups {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Mirrors an XML dump of a source domain's groups to a target test domain.
    
    .DESCRIPTION
        Creates groups contained in a backup XML file in a target domain. Does not create groups if 
        they already exist. Does not create groups if the parent OU does not already exist.
    
        Populates groups memberships. IMPORTANT: Foreign Security Principals won't be added.
    
        Intended to be used with a sister function that dumps the groups from a source domain.

        Logs all function actions to a date and time named log.

        Requirements:

            * PowerShell ActiveDirectory Module
            * An XML backup created by partner Dump-ADGroups function
            * Trace32.exe (SMS Trace) or CMTrace.exe (Configuration Manager Trace Log Tool) to view script log

    .EXAMPLE
        Mirror-ADGroups -Domain contoso.com -BackupXml .\150410093716_HALO_Group_Dump.xml

        Creates the groups contained in the 150410093716_HALO_Group_Dump.xml backup file in the contoso.com
        domain. Does not create groups if they already exist. Does not create groups if the parent OU does not
        already exist.  

        Writes a log file of all function actions.

    .EXAMPLE
        Mirror-ADGroups -Domain contoso.com 
                        -BackupXml .\150410093716_HALO_Group_Dump.xml
                        -TargetOu "OU=Test Groups,DC=Halo,DC=Net"

        Creates the groups contained in the 150410093716_HALO_Group_Dump.xml backup file in the contoso.com
        domain. Creates groups in the 'Test Groups' OU. Does not create Groups if they already exist. Does not 
        create Groups if the target OU does not exist.

        Writes a log file of all function actions.

    .OUTPUTS
        Date and time stamped log file, e.g. 150410110533_AD_Group_Mirror.log, for use with Trace32.exe (SMS Trace) 
        or CMTrace.exe (Configuration Manager Trace Log Tool)

        SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
        CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\


        EXIT CODES:  1 - Report file not found
                     2 - Custom XML Group file not found

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE.

        This sample is not supported under any Microsoft standard support program or service. 
        The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
        implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance
        of the sample and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the script be liable for 
        any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of 
        the use of or inability to use the sample or documentation, even if Microsoft has been advised 
        of the possibility of such damages, rising out of the use of or inability to use the sample script, 
        even if Microsoft has been advised of the possibility of such damages. 
    #>
    ##########################################################################################################

    #################################
    ## Function Options and Parameters
    #################################

    #Requires -version 3
    #Requires -modules ActiveDirectory


    #Define and validate parameters
    [CmdletBinding()]
    Param(
          #The target domain
          [parameter(Mandatory=$True,Position=1)]
          [ValidateScript({Get-ADDomain -Identity $_})] 
          [String]$Domain,

          #The source backup file 
          [parameter(Mandatory=$True,Position=2)]
          [ValidateScript({Test-Path -Path $_})]
          [String]$BackupXml,

          #Optional target OU 
          [parameter(Position=3)]
          [ValidateScript({Get-ADOrganizationalUnit -Identity $_})]
          [String]$TargetOu
          )


    #Set strict mode to identify typographical errors (uncomment whilst editing script)
    #Set-StrictMode -version Latest



    ##########################################################################################################

    ##############################
    ## FUNCTION - Log-ScriptEvent
    ##############################

    <#
       Write a line of data to a script log file in a format that can be parsed by Trace32.exe / CMTrace.exe

       The severity of the logged line can be set as:

            1 - Information
            2 - Warning
            3 - Error

       Warnings will be highlighted in yellow. Errors are highlighted in red.

       The tools:

       SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
       CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\
    #>

    Function Log-ScriptEvent {

        #Define and validate parameters
        [CmdletBinding()]
        Param(
              #Path to the log file
              [parameter(Mandatory=$True)]
              [String]$NewLog,

              #The information to log
              [parameter(Mandatory=$True)]
              [String]$Value,

              #The source of the error
              [parameter(Mandatory=$True)]
              [String]$Component,

              #The severity (1 - Information, 2- Warning, 3 - Error)
              [parameter(Mandatory=$True)]
              [ValidateRange(1,3)]
              [Single]$Severity
              )


        #Obtain UTC offset
        $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime 
        $DateTime.SetVarDate($(Get-Date))
        $UtcValue = $DateTime.Value
        $UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)


        #Create the line to be logged
        $LogLine =  "<![LOG[$Value]LOG]!>" +`
                    "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
                    "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
                    "component=`"$Component`" " +` 
                    "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
                    "type=`"$Severity`" " +`
                    "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
                    "file=`"`">"

        #Write the line to the passed log file
        Add-Content -Path $NewLog -Value $LogLine

    }   #End of Function Log-ScriptEvent


    ##########################################################################################################

    ########
    ## Main
    ########

    #Create a variable to represent a new script log, constructing the report name from date details
    $NewReport = ".\$(Get-Date -Format yyMMddHHmmss)_AD_Group_Mirror.log" 

    #Make sure the script log has been created
    if (New-Item -ItemType File -Path $NewReport) {

        ##Start writing to the script log (Start_Script)
        Log-ScriptEvent $NewReport ("=" * 90) "Start-Script" 1
        Log-ScriptEvent $NewReport "TARGET_DOMAIN: $Domain" "Start_Script" 1
        Log-ScriptEvent $NewReport "BACKUP_SOURCE: $BackupXml" "Start_Script" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Start_Script" 1
        Log-ScriptEvent $NewReport " " " " 1

        #Instantiate an object for the target domain
        $TargetDomain = Get-ADDomain -Identity $Domain

        #Obtain the target domain FQDN
        $TargetDomainFqdn = $TargetDomain.DNSRoot

        #Obtain the target domain DN
        $TargetDomainDn = $TargetDomain.DistinguishedName

        #Import the OU information contained in the XML file
        $GroupInfo = Import-Clixml -Path $BackupXml -ErrorAction SilentlyContinue

        #Make sure we have custom group info
        if ($GroupInfo) {

            #Log custom XML import success
            Log-ScriptEvent $NewReport "Custom Group objects successfully imported from $BackupXml" "Mirror_Groups" 1
            Log-ScriptEvent $NewReport " " " " 1 

            #Obtain the source domain DN from the first custom group object
            $SourceDomainDn = ($GroupInfo| Select -First 1).DomainDn

            #Create counters
            $i = 0    # groups processed
            $j = 0    # groups matched
            $k = 0    # groups created
            $l = 0    # group members processed
            $m = 0    # group creation failed
            $n = 0    # group members failed
            $o = 0    # groups processed (2)

            #Loop through each of the custom group objects
            foreach ($Group in $GroupInfo) {

                #Test that the group SamAccountName doesn't already exist
                try {$TargetGroupSAM = Get-ADGroup -Identity $Group.SamAccountName -Server $TargetDomainFqdn}
                catch {}

                #If we have a group then onwards...
                if ($TargetGroupSAM) {

                    #Log that object exists
                    Log-ScriptEvent $NewReport "SamAccountName - `"$(($Group).SamAccountName)`" - already exists in $Domain" "Mirror_Groups" 1
            
                    #Increment group matched counter
                    $j++

                }   #End of if ($TargetGroupSAM)

                else {

                    #Log that object does not exist
                    Log-ScriptEvent $NewReport "SamAccountName - `"$(($Group).SamAccountName)`" - does not exist in $Domain" "Mirror_Groups" 1

                    #Test that the group Name doesn't already exist
                    try{$TargetgroupName = Get-ADGroup -Identity $Group.Name -Server $TargetDomainFqdn}
                    catch {}

                    #If we have a group then onwards...
                    if ($TargetgroupName) {

                        #Log that object exists
                        Log-ScriptEvent $NewReport "Group Name - `"$(($Group).Name)`" - already exists in $Domain" "Mirror_Groups" 1
            
                        #Increment group matched counter
                        $j++

                    }   #End of if ($TargetgroupName)

                    else {

                        #Log that object does not exist
                        Log-ScriptEvent $NewReport "Group Name - `"$(($Group).Name)`" - does not exist in $Domain" "Mirror_Groups" 1

                        #Update the managedBy attribute if it exists
                        if ($Group.managedBy) {

                            #Replace domain portion of DN
                            $ManagedBy = $Group.managedBy -replace $SourceDomainDn,$TargetDomainDn

                        }   #end of if ($Group.managedBy)

                        #Determine where we create the group
                        if ($TargetOu) {

                            #Log that we are using a parameter value as our target OU
                            Log-ScriptEvent $NewReport "Using supplied paramter - $TargetOu - as group parent OU" "Mirror_Groups" 1  
                    
                            #Attempt to create group in Target OU
                            $Newgroup = New-ADgroup -Name $Group.Name `                                                    -GroupCategory $Group.GroupCategory `                                                    -GroupScope $Group.GroupScope `                                                    -SamAccountName $Group.SamAccountName `                                                    -DisplayName $Group.DisplayName `                                                    -Description $Group.Description `                                                    -Path $TargetOu `                                                    -ErrorAction SilentlyContinue

                            #Check the success of the New-ADgroup cmdlet
                            if ($?) {

                                #Log success of New-ADgroup cmdlet
                                Log-ScriptEvent $NewReport "Creation of `"$(($Group).SamAccountName)`" succeeded." "Mirror_Groups" 1
                            
                                #Increment group created counter
                                $k++


                            }   #End of if ($?)

                            else {

                                #Log failure of New-ADgroup cmdlet
                                Log-ScriptEvent $NewReport "Creation of `"$(($Group).SamAccountName)`" failed. $($Error[0].exception.message)" "Mirror_Groups" 3   

                                #Increment group creation failed counter
                                $m++


                            }   #End of else ($?)                      


                    }   #End of if ($TargetOu)
                        else {

                            #Replace the domain DN with the target filter DN for our parent path
                            $TargetParentDn = $Group.ParentDn –Replace $SourceDomainDn,$TargetDomainDn

                            #Test that the parent exists
                            Try{$TargetParent = Get-ADObject -Identity $TargetParentDn -Server $TargetDomainFqdn}
                            Catch {}

                            #Check to see that the parent OU already exists
                            if ($TargetParent) {

                                #Log that object exists
                                Log-ScriptEvent $NewReport "`"$TargetParentDn`" parent already exists in $Domain" "Mirror_Groups" 1

                                #Attempt to create group in Target OU
                                $Newgroup = New-ADgroup -Name $Group.Name `                                                        -GroupCategory $Group.GroupCategory `                                                        -GroupScope $Group.GroupScope `                                                        -SamAccountName $Group.SamAccountName `                                                        -DisplayName $Group.DisplayName `                                                        -Description $Group.Description `                                                        -Path $TargetParentDn `                                                        -ErrorAction SilentlyContinue


                                    #Check the success of the New-ADgroup cmdlet
                                    if ($?) {

                                        #Log success of New-ADgroup cmdlet
                                        Log-ScriptEvent $NewReport "Creation of `"$(($Group).SamAccountName)`" succeeded." "Mirror_Groups" 1
                                
                                        #Increment group created counter
                                        $k++


                                    }   #End of if ($?)

                                    else {

                                        #Log failure of New-ADgroup cmdlet
                                        Log-ScriptEvent $NewReport "Creation of `"$(($Group).SamAccountName)`" failed. $($Error[0].exception.message)" "Mirror_Groups" 3 

                                        #Increment group creation failed counter
                                        $m++


                                    }   #End of else ($?) 

                            }   #End of if ($TargetParent)
                            else {

                                #Log that object does not exist 
                                Log-ScriptEvent $NewReport "`"$TargetParentDn`" parent does not exist in $Domain... group creation will not be attempted" "Mirror_Groups" 1
                                Log-ScriptEvent $NewReport " " " " 1 

                            }   #End of else ($TargetParent)

                        }   #End of else ($TargetOu)

                    }   #End of else ($TargetgroupName)

                }   #End of else ($TargetGroupSAM)


                #Spin up a progress bar for each filter processed
                Write-Progress -Activity "Mirroring Groups to $TargetDomainFqdn" -Status "Processed: $i" -PercentComplete -1

                #Increment the group processed counter
                $i++

                #Nullify key variables
                $TargetGroupSAM = $null
                $TargetGroupName = $null
                $TargetGroupDn = $null
                $TargetParent = $null


            }   #End of foreach($Group in $GroupInfo)

            #Now we need to loop through the groups again to process membership
            foreach ($Group in $GroupInfo) {

                #Replace the existing domain DN with the DN for group in the target domain
                $TargetGroupDn = $Group.GroupDn –Replace $SourceDomainDn,$TargetDomainDn

                #Spacer
                Log-ScriptEvent $NewReport " " " " 1 

                #Loop through the members attribute
                foreach ($Member in $Group.members) {
                
                    #Replace the existing member DN with the DN for the member in the target domain
                    $TargetMemberDn = $Member –Replace $SourceDomainDn,$TargetDomainDn

                    #Attempt to add the member to the group
                    $NewMember = Add-ADGroupMember -Identity $TargetGroupDn -Members $TargetMemberDn -Server $Domain -ErrorAction SilentlyContinue

                        #Check the success of the New-ADGroupMember cmdlet
                        if ($?) {

                            #Log success of New-ADGroupMember cmdlet
                            Log-ScriptEvent $NewReport "Addition of $TargetMemberDn to $TargetGroupDn succeeded." "Add_Members" 1 
                    
                            #Increment group addition counter
                            $l++


                        }   #End of if ($?)

                        else {

                            #Log failure of New-ADGroup cmdlet
                            Log-ScriptEvent $NewReport "Addition of $TargetMemberDn to $TargetGroupDn failed. $($Error[0].exception.message)" "Add-Members" 3   

                            #Increment group addition failed counter
                            $n++


                        }   #End of else ($?)

                        #Nullify variable
                        $TargetMemberDn = $null

                }   #End of foreach ($Member in $Group.members)            

                #Spin up a progress bar for each filter processed
                Write-Progress -Activity "Updating group membership in $TargetDomainFqdn" -Status "Groups processed: $o" -PercentComplete -1

                #Increment the group processed counter
                $o++

                #Nullify variable
                $TargetGroupDn = $null

            }   #End of foreach($Group in $GroupInfo)


        }   #End of if ($GroupInfo)

        else {

        #Log failure to import custom group XML object
        Log-ScriptEvent $NewReport "$BackupXml import failed" "Mirror_Groups" 3
        Log-ScriptEvent $NewReport "Script execution stopped" "Mirror_Groups" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Mirror_Groups" 1
        Write-Error "$BackupXml not found. Script execution stopped."
        Exit 2

        }   #End of else ($GroupInfo)


        #Close of the script log
        Log-ScriptEvent $NewReport " " " " 1 
        Log-ScriptEvent $NewReport ("=" * 90) "Finish_Script" 1
        Log-ScriptEvent $NewReport "GROUPS_PROCESSED: $i" "Finish_Script" 1
        Log-ScriptEvent $NewReport "GROUPS_MATCHED: $j" "Finish_Script" 1
        Log-ScriptEvent $NewReport "GROUPS_CREATED_SUCCESS: $k" "Finish_Script" 1
        Log-ScriptEvent $NewReport "GROUPS_CREATED_FAILURE: $m" "Finish_Script" 1
        Log-ScriptEvent $NewReport "MEMBERS_ADDED_SUCCESS: $l" "Finish_Script" 1
        Log-ScriptEvent $NewReport "MEMBERS_ADDED_FAILURE: $n" "Finish_Script" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Finish_Script" 1


    }   #End of if (New-Item -ItemType File -Path $NewReport)

    else {

        #Write a custom error
        Write-Error "$NewReport not found. Script execution stopped."
        Exit 1

    }   #End of else (New-Item -ItemType File -Path $NewReport)

}   #end of function Mirror-ADGroups



##########################
#FUNCTION 7: Dump-ADGpos
##########################

function Dump-ADGpos {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Backs up GPOs from a specified domain and includes additional GPO information.

    .DESCRIPTION
        The function backs up GPOs in a target domain and captures additional GPO management information, such
        as Scope of Management, Block Inheritance, Link Enabled, Link Order, Link Enforced and WMI Filters.

        The backup can then be used by a partner function to mirror GPOs in a test domain.

        Details:
        * Creates a XML file containing PSCustomObjects used by partner import function
        * Creates a XML file WMI filter details used by partner import function
        * Creates a CSV file of additional information for readability
        * Creates a folder containing HTML reports of settings for each GPO
        * Additional backup information includes SOM (Scope of Management) Path, Block Inheritance, Link Enabled,
          Link Order', Link Enforced and WMI Filter data
        * Each CSV SOM entry is made up of "DistinguishedName:BlockInheritance:LinkEnabled:LinkOrder:LinkEnforced"
        * Option to create a Migration Table (to then be manually updated)

        Requirements: 
        * PowerShell GroupPolicy Module
        * PowerShell ActiveDirectory Module
        * Group Policy Management Console

    .EXAMPLE
       Dump-ADGpos -Domain wintiptoys.com -BackupFolder "\\wingdc01\backups\"

       This will backup all GPOs in the domain wingtiptoys.com and store them in a date and time stamped folder 
       under \\wingdc01\backups\.

    .EXAMPLE
       Dump-ADGpos -Domain contoso.com -BackupFolder "c:\backups" -MigTable

       This will backup all GPOs in the domain contoso.com and store them in a date and time stamped folder 
       under c:\backups\. A migration table, MigrationTable.migtable, will also be created for manual editing.

    .EXAMPLE
       Dump-ADGpos -Domain contoso.com -BackupFolder "c:\backups" -ModifiedDays 15

       This will backup all GPOs in the domain contoso.com that have been modified within the last 15 days. 
       The function will store the backed up GPOs in a date and time stamped folder under c:\backups\

    .EXAMPLE
       Dump-ADGpos -Domain adatum.com -BackupFolder "c:\backups" -GpoGuid "b1e0e5ea-0d6b-48f1-a56c-0a98d8acd17b"

       This will backup the GPO identified by the following GUID - "b1e0e5ea-0d6b-48f1-a56c-0a98d8acd17b" - from the 
       domain adatum.com

       The backed up GPO will be stored in a date and time stamped folder under c:\backups\

    .OUTPUTS
       * Backup folder name in the format Year_Month_Day_HourMinuteSecond
       * Per-GPO HTML settings report in the format <backup-guid>__<gpo-guid>__<gpo-name>.html
       * GpoDetails.xml
       * Wmifilters.xml
       * GpoInformation.csv
       * MigrationTable.migtable (optional)

       EXIT CODES: 1 - GPMC not found

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE.

        This sample is not supported under any Microsoft standard support program or service. 
        The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
        implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance
        of the sample and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the script be liable for 
        any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of 
        the use of or inability to use the sample or documentation, even if Microsoft has been advised 
        of the possibility of such damages, rising out of the use of or inability to use the sample script, 
        even if Microsoft has been advised of the possibility of such damages. 

    #>
    ##########################################################################################################

    #################################
    ## Function Options and Parameters
    #################################

    #Requires -version 3
    #Requires -modules ActiveDirectory,GroupPolicy

    #Version: 2.4
    <#   
         - 2.1 - 19/08/2014 
         * the script now processes gPLink info on site objects
         * thanks to Mark Renoden [MSFT]

         - 2.2 - 08/07/2015 
         * updates to allow backup from one trusted forest to another

         - 2.3 - 12/01/2016 
         * added ability to backup GPOs modified within the last X days
         * added ability to create html report of settings per GPO
         * thanks to Marcus Carvalho [MSFT]

         - 2.4 - 15/01/2016 
         * added ability to backup a single GPO
         * added parameter sets to prevent -GpoGuid and -ModifiedDate being used together
    #>

    #Define and validate parameters
    [CmdletBinding(DefaultParameterSetName="All")]
    Param(
          #The target domain
          [parameter(Mandatory=$True,Position=1)]
          [ValidateScript({Get-ADDomain $_})] 
          [String]$Domain,

          #The backup folder
          [parameter(Mandatory=$True,Position=2)]
          [ValidateScript({Test-Path $_})]
          [String]$BackupFolder,

          #Backup GPOs modified within the last X days
          [parameter(ParameterSetName="Modified",Mandatory=$False,Position=3)]
          [ValidateSet(15,30,45,60,90)]
          [Int]$ModifiedDays,

          #Backup a single GPO
          [parameter(ParameterSetName="Guid",Mandatory=$False,Position=3)]
          [ValidateScript({Get-GPO -Guid $_})] 
          [String]$GpoGuid,

          #Whether to create a migration table
          [Switch]$MigTable
        )


    #Set strict mode to identify typographical errors (uncomment whilst editing script)
    #Set-StrictMode -version Latest


    ##########################################################################################################

    ########
    ## Main
    ########


    ########################
    ##BACKUP FOLDER DETAILS
    #Create a variable to represent a new backup folder
    #(constructing the report name from date details and the supplied backup folder)
    $Date = Get-Date
    $ShortDate = Get-Date -format d

    $SubBackupFolder = "$BackupFolder\" + `                       "$($Date.Year)_" + `                       "$("{0:D2}" -f $Date.Month)_" + `                       "$("{0:D2}" -f $Date.Day)_" + `                       "$("{0:D2}" -f $Date.Hour)" + `                       "$("{0:D2}" -f $Date.Minute)" + `                       "$("{0:D2}" -f $Date.Second)"


    ##################
    ##BACKUP ALL GPOs
    #Create the backup folder
    New-Item -ItemType Directory -Path $SubBackupFolder | Out-Null

    #Create the settings report folder
    $HtmlReports = "HTML_Reports"
    New-Item -ItemType Directory -Path "$SubBackupFolder\$HtmlReports" | Out-Null


    #Make sure the backup folders have been created
    if ((Test-Path -Path $SubBackupFolder) -and (Test-Path -Path "$SubBackupFolder\$HtmlReports")) {

        #Connect to the supplied domain
        $TargetDomain = Get-ADDomain -Identity $Domain
    

        #Obtain the domain FQDN
        $DomainFQDN = $TargetDomain.DNSRoot


        #Obtain the domain DN
        $DomainDN = $TargetDomain.DistinguishedName


        #Connect to the forest root domain
        $TargetForestRootDomain = (Get-ADForest -Server $DomainFQDN).RootDomain | Get-ADDomain
    

        #Obtain the forest FQDN
        $ForestFQDN = $TargetForestRootDomain.DNSRoot


        #Obtain the forest DN
        $ForestDN = $TargetForestRootDomain.DistinguishedName    

	
        #Create an empty array for our backups
	    $Backups = @()

            #Determine the type of backup to be performed
	        if ($ModifiedDays) {

                #Get a list of
		        $ModGpos = Get-GPO -Domain $DomainFQDN -All | Where-Object {$_.ModificationTime -gt $Date.AddDays(-$ModifiedDays)}
            
                #Loop through each recently changed GPO and back it up, adding the resultant object to the $Backups array
                foreach ($ModGpo in $ModGpos) {

			        $Backups += Backup-GPO $ModGpo.DisplayName -Path $SubBackupFolder -Comment "Scripted backup created by $env:userdomain\$env:username on $ShortDate"
		    

                }   #end of foreach ($ModGpo in $ModGpos)

	        }   #end of if ($ModifiedDays)
            elseif ($GpoGuid) {

                #Backup single GPO
                 $Backups = Backup-GPO -Guid $GpoGuid -Path $SubBackupFolder -Domain $DomainFQDN -Comment "Scripted backup created by $env:userdomain\$env:username on $ShortDate"

            }   #end of elseif ($GpoGuid)
	        else {
		    
		        #Backup all GPOs found in the domain
                $Backups = Backup-GPO -All -Path $SubBackupFolder -Domain $DomainFQDN -Comment "Scripted backup created by $env:userdomain\$env:username on $ShortDate"

		    
	        }   #end of else ($ModifiedDays)

	
            #Instantiate an object for Group Policy Management (GPMC required)
            try {

                $GPM = New-Object -ComObject GPMgmt.GPM
    
            }   #end of Try...
    
            catch {

                #Display exit message to console
                $Message = "ERROR: Unable to connect to GPMC. Please check that it is installed."
                Write-Host
                Write-Error $Message
  
                #Exit the script
                exit 1
    
            }   #end of Catch...


        #Import the GPM API constants
        $Constants = $GPM.getConstants()


        #Connect to the supplied domain
        $GpmDomain = $GPM.GetDomain($DomainFQDN,$Null,$Constants.UseAnyDc)

    
        #Connect to the sites container
        $GpmSites = $GPM.GetSitesContainer($ForestFQDN,$DomainFQDN,$Null,$Constants.UseAnyDc)
    

        ###################################
        ##COLLECT SPECIFIC GPO INFORMATION
        #Loop through each backed-up GPO
        foreach ($Backup in $Backups) {

            #Get the GPO GUID for our target GPO
            $GpoGuid = $Backup.GpoId


            #Get the backup GUID for our target GPO
            $BackupGuid = $Backup.Id
        

            #Instantiate an object for the relevant GPO using GPM
            $GPO = $GpmDomain.GetGPO("{$GpoGuid}")


            #Get the GPO DisplayName property
            $GpoName = $GPO.DisplayName

            #Get the GPO ID property
            $GpoID = $GPO.ID
	
            
		    ##Retrieve SOM Information
		    #Create a GPM search criteria object
		    $GpmSearchCriteria = $GPM.CreateSearchCriteria()


		    #Configure search critera for SOM links against a GPO
		    $GpmSearchCriteria.Add($Constants.SearchPropertySOMLinks,$Constants.SearchOpContains,$GPO)


		    #Perform the search
		    $SOMs = $GpmDomain.SearchSOMs($GpmSearchCriteria) + $GpmSites.SearchSites($GpmSearchCriteria)


		    #Empty the SomPath variable
		    $SomInfo = $Null

		
		    #Loop through any SOMs returned and write them to a variable
		    foreach ($SOM in $SOMs) {

			    #Capture the SOM Distinguished Name
			    $SomDN = $SOM.Path

		
			    #Capture Block Inheritance state
			    $SomInheritance = $SOM.GPOInheritanceBlocked

		
			    #Get GPO Link information for the SOM
			    $GpoLinks = $SOM.GetGPOLinks()


				    #Loop through the GPO Link information and match info that relates to our current GPO
				    foreach ($GpoLink in $GpoLinks) {
				
					    if ($GpoLink.GPOID -eq $GpoID) {

						    #Capture the GPO link status
						    $LinkEnabled = $GpoLink.Enabled


						    #Capture the GPO precedence order
						    $LinkOrder = $GpoLink.SOMLinkOrder


						    #Capture Enforced state
						    $LinkEnforced = $GpoLink.Enforced


					    }   #end of if ($GpoLink.GPOID -eq $GpoID)


				    }   #end of foreach ($GpoLink in $GpoLinks)


			    #Append the SOM DN, link status, link order and Block Inheritance info to $SomInfo
			    [Array]$SomInfo += "$SomDN`:$SomInheritance`:$LinkEnabled`:$LinkOrder`:$LinkEnforced"
	
	
		    }   #end of foreach ($SOM in $SOMs)...


            ##Obtain WMI Filter path using Get-GPO
            $Wmifilter = (Get-GPO -Guid $GpoGuid -Domain $DomainFQDN).WMifilter.Path
        
            #Split the value down and use the ID portion of the array
            #$WMifilter = ($Wmifilter -split "`"")[1]
            $WMifilter = ($Wmifilter -split '"')[1]



            #Add selected GPO properties to a custom GPO object
            $GpoInfo = [PSCustomObject]@{

                    BackupGuid = $BackupGuid
                    Name = $GpoName
                    GpoGuid = $GpoGuid
                    SOMs = $SomInfo
                    DomainDN = $DomainDN
                    Wmifilter = $Wmifilter
        
            }   #end of $Properties...

        
            #Add our new object to an array
            [Array]$TotalGPOs += $GpoInfo


        }   #end of foreach ($Backup in $Backups)...



        #####################
        ##BACKUP WMI FILTERS
        #Connect to the Active Directory to get details of the WMI filters
        $Wmifilters = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' `                                   -Properties msWMI-Author, msWMI-ID, msWMI-Name, msWMI-Parm1, msWMI-Parm2 `                                   -Server $DomainFQDN `                                   -ErrorAction SilentlyContinue



        ######################
        ##CREATE REPORT FILES
        ##XML reports
        #Create a variable for the XML file representing custom information about the backed up GPOs
        $CustomGpoXML = "$SubBackupFolder\GpoDetails.xml"

        #Export our array of custom GPO objects to XML so they can be easily re-imported as objects
        $TotalGPOs | Export-Clixml -Path $CustomGpoXML

        #if $WMifilters contains objects write these to an XML file
        if ($Wmifilters) {

            #Create a variable for the XML file representing the WMI filters
            $WmiXML = "$SubBackupFolder\Wmifilters.xml"

            #Export our array of WMI filters to XML so they can be easily re-imported as objects
            $Wmifilters | Export-Clixml -Path $WmiXML

        }   #end of if ($Wmifilters)


        ##CSV report / HTML Settings reports
        #Create a variable for the CSV file that will contain the SOM (Scope of Management) information for each backed-up GPO
        $SOMReportCSV = "$SubBackupFolder\GpoInformation.csv"

        #Now, let's create the CSV report and the HTML settings reports
        foreach ($CustomGPO in $TotalGPOs) {
        
            ##CSV report stuff    
            #Start constructing the CSV file line entry for the current GPO
            $CSVLine = "`"$($CustomGPO.Name)`",`"{$($CustomGPO.GPOGuid)}`","


            #Expand the SOMs property of the current object
            $CustomSOMs = $CustomGPO.SOMs


                #Loop through any SOMs returned
                foreach ($CustomSOM in $CustomSOMs) {

                    #Append the SOM path to our CSV line
                    $CSVLine += "`"$CustomSOM`","

         
               }   #end of foreach ($CustomSOM in $CustomSOMs)...


           #Write the newly constructed CSV line to the report
           Add-Content -Path $SOMReportCSV -Value $CSVLine


           ##HTML settings report stuff
	       #Remove invalid characters from GPO display name
	       $GpoCleanedName = $CustomGPO.Name -replace "[^1-9a-zA-Z_]", "_"
	
           #Create path to html file
	       $ReportPath = "$SubBackupFolder\$HtmlReports\$($CustomGPO.BackupGuid)___$($CustomGPO.GpoGuid)__$($GpoCleanedName).html"
	
           #Create GPO report
           Get-GPOReport -Guid $CustomGPO.GpoGuid -Path $ReportPath -ReportType HTML 


        }   #end of foreach ($CustomGPO in $TotalGPOs)...



        ###########
        ##MIGTABLE
        #Check whether a migration table should be created
        if ($MigTable) {

            #Create a variable for the migration table
            $MigrationFile = "$SubBackupFolder\MigrationTable.migtable"

            #Create a migration table 
            $MigrationTable = $GPM.CreateMigrationTable()


            #Connect to the backup directory
            $GpmBackupDir = $GPM.GetBackUpDir($SubBackupFolder)

            #Reset the GPM search criterea
            $GpmSearchCriteria = $GPM.CreateSearchCriteria()


            #Configure search critera for the most recent backup
            $GpmSearchCriteria.Add($Constants.SearchPropertyBackupMostRecent,$Constants.SearchOpEquals,$True)
   

            #Get GPO information
            $BackedUpGPOs = $GpmBackupDir.SearchBackups($GpmSearchCriteria)


                #Add the information to our migration table
                foreach ($BackedUpGPO in $BackedUpGPOs) {

                    $MigrationTable.Add($Constants.ProcessSecurity,$BackedUpGPO)
        
                }   #end of foreach ($BackedUpGPO in $BackedUpGPOs)...


            #Save the migration table
            $MigrationTable.Save($MigrationFile)


        }   #end of if ($MigTable)...


    }   #end of if ((Test-Path -Path $SubBackupFolder) -and (Test-Path -Path "$SubBackupFolder\$HtmlReports"))...
    else {

        #Write error
        Write-Error -Message "Backup path validation failed"


    }   #end of ((Test-Path -Path $SubBackupFolder) -and (Test-Path -Path "$SubBackupFolder\$HtmlReports"))

}   #end of function Dump-ADGpos



############################
#FUNCTION 8: Mirror-ADGpos
############################

function Mirror-ADGpos {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Imports all GPOs from a backup folder into a test domain. Additional GPO information can be imported.

    .DESCRIPTION
        The function is intended to import backed up GPOs to a test domain. For the additional GPO information
        functionality, a backup created by the partner Dump-ADGpos function should be used.

        Details:
        * Can use a Migration Table to translate domain specific information
        * Can import SOM (Scope of Management) Path, Block Inheritance, Link Enabled, Link Order and Enforced
          settings
        * Can import and link WMI filters
        * If set by the function, 'Block Inheritance' and 'Enforced' settings are highlighted as warnings (yellow) 
          in the function log

        Requirements:
        * PowerShell GroupPolicy Module
        * PowerShell ActiveDirectory Module
        * A backup created by partner Dump-ADGpos function
        * Trace32.exe (SMS Trace) or CMTrace.exe (Configuration Manager Trace Log Tool) to view function log
        * SOM paths, e.g. OU heirachy, in target domain matches source domain to reinstate additional information

    .EXAMPLE
       Mirror-ADGpos -Domain northwindtraders.com -BackupFolder "\\corpdc01\backups\"

       This will import all backed-up GPOs from \\corpdc01\backups into the northwindtraders domain.
       No additional GPO infomation is imported.

    .EXAMPLE
       Mirror-ADGpos -Domain fabrikam.com -BackupFolder "d:\backups" -MigTable

       This will import all backed-up GPOs from d:\backups into the fabrikam domain.
       The import will look for a migration table in the backup folder and attempt to translate the values.

    .EXAMPLE
       Mirror-ADGpos -Domain northwindtraders.com -BackupFolder "\\corpdc01\backups\" -SomInfo

       This will import all backed-up GPOs from \\corpdc01\backups into the northwindtraders domain.
       The import will attempt to recreate GPO links and their precedence. Block Inheritance and Enforced
       details will also be restored, if possible.

    .EXAMPLE
       Mirror-ADGpos -Domain northwindtraders.com -BackupFolder "\\corpdc02\backups\" -WmiFilter

       This will import all backed-up GPOs from \\corpdc02\backups into the northwindtraders domain.
       The import will attempt to recreate WMI filters and link them to matching policies.

    .EXAMPLE
       Mirror-ADGpos -Domain fabrikam.com -BackupFolder "d:\backups" -MigTable -SomInfo -WMiFilter

       This will import all backed-up GPOs from d:\backups into the fabrikam domain.
       The import will look for a migration table in the backup folder and attempt to translate the values.
       The import will also attempt to recreate GPO links and their precedence. Block Inheritance and Enforced
       details will also be restored, if possible. The import will attempt to recreate WMI filters and link 
       them to matching policies.

    .OUTPUTS
       Time and date stamped import log for use with Trace32.exe (SMS Trace) or CMTrace.exe (Configuration Manager Trace Log Tool)

       SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
       CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\


       EXIT CODES:  1 - Report file not found
                    2 - Custom GPO XML file not found
                    3 - Migration file not found

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE.

        This sample is not supported under any Microsoft standard support program or service. 
        The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
        implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance
        of the sample and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the script be liable for 
        any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of 
        the use of or inability to use the sample or documentation, even if Microsoft has been advised 
        of the possibility of such damages, rising out of the use of or inability to use the sample script, 
        even if Microsoft has been advised of the possibility of such damages. 
    #>
    ##########################################################################################################

    #################################
    ## Function Options and Parameters
    #################################

    #Requires -version 3
    #Requires -modules ActiveDirectory,GroupPolicy

    #Version: 2.0

    #Define and validate parameters
    [CmdletBinding()]
    Param(
          #The target domain
          [parameter(Mandatory=$True,Position=1)]
          [ValidateScript({Get-ADDomain -Identity $_})] 
          [String]$Domain,

          #The source backup folder (use full path)
          [parameter(Mandatory=$True,Position=2)]
          [ValidateScript({Test-Path -Path $_})]
          [String]$BackupFolder,

          # Whether to reference a migration table
          [Switch] 
          $MigTable,

          # Whether to import SOM information
          [Switch] 
          $SomInfo,

          # Whether to import WMI filter information
          [Switch] 
          $WmiFilter
          )


    #Set strict mode to identify typographical errors (uncomment whilst editing script)
    #Set-StrictMode -version Latest



    ##########################################################################################################

    ##############################
    ## FUNCTION - Log-ScriptEvent
    ##############################

    <#
       Write a line of data to a script log file in a format that can be parsed by Trace32.exe / CMTrace.exe

       The severity of the logged line can be set as:

            1 - Information
            2 - Warning
            3 - Error

       Warnings will be highlighted in yellow. Errors are highlighted in red.

       The tools:

       SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
       CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\
    #>

    Function Log-ScriptEvent {

    #Define and validate parameters
    [CmdletBinding()]
    Param(
          #Path to the log file
          [parameter(Mandatory=$True)]
          [String]$NewReport,

          #The information to log
          [parameter(Mandatory=$True)]
          [String]$Value,

          #The source of the error
          [parameter(Mandatory=$True)]
          [String]$Component,

          #The severity (1 - Information, 2- Warning, 3 - Error)
          [parameter(Mandatory=$True)]
          [ValidateRange(1,3)]
          [Single]$Severity
          )
    #Create the line to be logged    $LogLine =  "<![LOG[$Value]LOG]!>" +`                "<time=`"$(Get-Date -Format HH:mm:ss).000+0`" " +`                "date=`"$(Get-Date -Format M-d-yyyy)`" " +`                "component=`"$Component`" " +` 
                "context=`"`" " +`                "type=`"$Severity`" " +`                "thread=`"1`" " +`                "file=`"`">"

    #Write the line to the passed log file
    Add-Content -Path $NewReport -Value $LogLine

    }


    ##########################################################################################################

    ########
    ## Main
    ########

    #Create a variable to represent a new script log, constructing the report name from date details
    $SourceParent = (Get-Location).Path
    $Date = Get-Date #-Format yyMMddhhss
    $NewReport = "$SourceParent\" + `                 "$($Date.Year)" + `                 "$("{0:D2}" -f $Date.Month)" + `                 "$("{0:D2}" -f $Date.Day)" + `                 "$("{0:D2}" -f $Date.Hour)" + `                 "$("{0:D2}" -f $Date.Minute)" + `                 "$("{0:D2}" -f $Date.Second)" + `
                 "_GPO_Import.log"



    #Make sure the script log has been created
    If (New-Item -ItemType File -Path $NewReport) {

        ##Start writing to the script log (Start_Script)
        Log-ScriptEvent $NewReport ("=" * 90) "Start-Script" 1
        Log-ScriptEvent $NewReport "TARGET_DOMAIN: $Domain" "Start_Script" 1
        Log-ScriptEvent $NewReport "BACKUP_SOURCE: $BackupFolder" "Start_Script" 1
        Log-ScriptEvent $NewReport "MIGRATION_TABLE: $MigTable" "Start_Script" 1
        Log-ScriptEvent $NewReport "SOM_INFO: $SomInfo" "Start_Script" 1
        Log-ScriptEvent $NewReport "WMI_FILTERS: $WmiFilter" "Start_Script" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Start_Script" 1
        Log-ScriptEvent $NewReport " " " " 1



        ##Define variables used throughout the script sections
        #Instantiate an object for the target domain
        $TargetDomain = Get-ADDomain $Domain

        #Obtain the target domain FQDN
        $TargetDomainFQDN = $TargetDomain.DNSRoot

        #Obtain the target domain DN
        $TargetDomainDN = $TargetDomain.DistinguishedName

        #Obtain the target domain PDCe
        $TargetPDC = $TargetDomain.PDCEmulator

        #Create a variable for the Custom GPO XML file
        $CustomGpoXML = "$BackupFolder\GpoDetails.xml"

        #Import the custom GPO information contained in the XML file
        $CustomGpoInfo = Import-Clixml -Path $CustomGpoXML

        #Obtain the source domain DN from the first custom GPO object
        $SourceDomainDN = ($CustomGpoInfo | Select -First 1).DomainDN



        ##################################
        ###Section 1 - Import WMI filters
        ##Create or update WMI filters in Active Directory if the -WmiFilter switch is specified (Import_WMI)
        #Make sure we have custom GPO info
        If ($CustomGpoInfo) {

            #Log custom GPO import success
            Log-ScriptEvent $NewReport "Custom GPO objects successfully imported from $CustomGpoXML" "Import_GPOs" 1
            Log-ScriptEvent $NewReport " " " " 1

            #Check whether the WMI filters should be imported
            If ($WmiFilter) {

                #Create a variable for the XML file representing the WMI filters
                $WmiXML = "$BackupFolder\WmiFilters.xml"


                #Import the WMI filter information contained in the XML file
                $WmiFilters = Import-Clixml -Path $WmiXML


                #Make sure we have WMI filter information
                If ($WmiFilters) {

                    #Log WMI filter XML import success
                    Log-ScriptEvent $NewReport "WMI f$Tailter objects successfully imported from $WmiXML" "Import_WMI" 1


                    #Create a filter counter
                    $k = 0

                    #Loop through each of the WMI filters
                    ForEach ($WMI in $WmiFilters) {

                        #Replace the domain DN with the target filter DN
                        $TargetWmiDN = $WMI.DistinguishedName –Replace $SourceDomainDN, $TargetDomainDN


                        #Ensure that the msWMI-Parm1 property (the WMI Filter Description in the GUI) is populated
                        If (!($WMI."msWMI-Parm1")) {

                            #Set the description as a single space to avoid an error
                            $Parm1 = " "


                        }   #End of If (!($WMI."msWMI-Parm1"))
                     
                        Else {

                            #Use the current filter's description property
                            $Parm1 = $WMI."msWMI-Parm1"


                        }   #End of Else (!($WMI."msWMI-Parm1"))


                        #Test that the WMI filter doesn't already exist
                        $TargetWMI = (Get-ADObject -Identity $TargetWmiDN -Server $TargetPDC -ErrorAction SilentlyContinue)


                        #If the object already exists then just update it
                        If ($TargetWMI) {

                            #Log that object exists
                            Log-ScriptEvent $NewReport "`"$($WMI."msWMI-Name") - $($WMI."msWMI-ID")`" already exists in $Domain - attempting to update..." "Import_WMI" 1
                        
                            #Define properties to be passed to Set-ADObject
                            $Properties = [Ordered]@{

                                "msWMI-Author" = $WMI."msWMI-Author"
                                "msWMI-ChangeDate" = "$(Get-Date -Format yyyyMMddhhmmss).706000-000"
                                "msWMI-ID" = $WMI."msWMI-ID"  
                                "msWMI-Name" = $WMI."msWMI-Name"
                                "msWMI-Parm1" = $Parm1
                                "msWMI-Parm2" = $WMI."msWMI-Parm2"


                            }   #End of $Properties

                        
                            #Update the AD object
                            $UpdateWmiFilter = Set-ADObject -Identity $TargetWmiDN -Replace $Properties -Server $TargetPDC -ErrorAction SilentlyContinue


                                #Check the success of the Set-ADObject cmdlet
                                If ($?) {

                                    #Log success of Set-ADObject cmdlet
                                    Log-ScriptEvent $NewReport "Update of `"$($WMI."msWMI-Name") - $($WMI."msWMI-ID")`" succeeded." "Import_WMI" 1   


                                }   #End of If ($?)

                                Else {

                                    #Log failure of Set-ADObject cmdlet
                                    Log-ScriptEvent $NewReport "Update of `"$($WMI."msWMI-Name") - $($WMI."msWMI-ID")`" failed. $($Error[0].exception.message)" "Import_WMI" 3   

                                }   #End of Else ($?)

                        }   #End of If ($TargetWMI)

                        Else {

                            #Log that object does not exist
                            Log-ScriptEvent $NewReport "`"$($WMI."msWMI-Name") - $($WMI."msWMI-ID")`" does not exist in $Domain - attempting to create..." "Import_WMI" 1

                            #Define properties to be passed to Set-ADObject
                            $Properties = [Ordered]@{

                                "msWMI-Author" = $WMI."msWMI-Author"
                                "msWMI-ChangeDate" = "$(Get-Date -Format yyyyMMddhhmmss).706000-000"
                                "msWMI-CreationDate" = "$(Get-Date -Format yyyyMMddhhmmss).706000-000"
                                "msWMI-ID" = $WMI."msWMI-ID"  
                                "msWMI-Name" = $WMI."msWMI-Name"
                                "msWMI-Parm1" = $Parm1
                                "msWMI-Parm2" = $WMI."msWMI-Parm2"
                            }   #End of $Properties


                            #Create the AD object
                            $NewWmiFilter = New-ADObject -Name $WMI."msWMI-ID" -Type $WMI.ObjectClass `                                                         -Path "CN=SOM,CN=WMIPolicy,CN=System,$TargetDomainDN" `                                                         -OtherAttributes $Properties `                                                         -Server $TargetPDC `                                                         -ErrorAction SilentlyContinue

                                #Check the success of the New-ADObject cmdlet
                                If ($?) {

                                    #Log success of New-ADObject cmdlet
                                    Log-ScriptEvent $NewReport "Creation of `"$($WMI."msWMI-Name") - $($WMI."msWMI-ID")`" succeeded." "Import_WMI" 1   


                                }   #End of If ($?)

                                Else {

                                    #Log failure of New-ADObject cmdlet
                                    Log-ScriptEvent $NewReport "`"$($WMI."msWMI-Name") - $($WMI."msWMI-ID")`" failed. $($Error[0].exception.message)" "Import_WMI" 3   


                                }   #End of Else (?)


                        }   #End of Else ($TargetWMI)


                        #Spin up a progress bar for each filter processed
                        Write-Progress -activity "Importing WMI filters to $TargetDomainFQDN" -status "Processed: $k" -percentcomplete -1

                        #Increment the filter counter
                        $k++

                    }   #End of ForEach ($WMI in $WmiFilters)


                }   #End of If ($WmiFilters)

                Else {

                    #Log WMI filter XML import failure
                    Log-ScriptEvent $NewReport "WMI filter objects import failed from $WmiXML" "Import_WMI" 3


                }   #End of Else ($WmiFilters)


            }   #End of If ($WmiFilter)


            #####################################
            ###Section 2 - Import backed up GPOs 
            ##Perform a standard Import-GPO with or without a Migration Table (Import_GPOs)
            #A counter for each GPO processed 
            $i = 0


            #Loop through each Custom GPO object from the custom GPO array
            ForEach ($CustomGpo in $CustomGpoInfo) {
            
                #Log current GPO name
                Log-ScriptEvent $NewReport " " " " 1
                Log-ScriptEvent $NewReport "Processing policy - $($CustomGpo.Name)..." "Import_GPOs" 1
            

                #Check whether we're using a migration table for the GPO import
                If ($MigTable) {
                
                    #Create a variable for the migration table
                    $MigrationFile = "$BackupFolder\MigrationTable.migtable"


                    #Check that a migration table has been created by the backup function
                    If (Test-Path -Path $MigrationFile) {
                
                        #Log migration check
                        Log-ScriptEvent $NewReport "The import is referencing $MigrationFile" "Import_GPOs" 1


                        #Import all the GPOs referenced in the backup folder with a migration table
                        $ImportedGpo = Import-GPO -BackupId $CustomGpo.BackupGuid `                                                  -Path $BackupFolder `
                                                  -CreateIfNeeded `                                                  -Domain $TargetDomainFQDN `                                                  -TargetName $CustomGpo.Name `
                                                  -MigrationTable $MigrationFile `
                                                  -Server $TargetPDC `
                                                  -ErrorAction SilentlyContinue

                
                            #Log the outcome of $ImportedGpo
                            If ($?) {

                                Log-ScriptEvent $NewReport "Import of $($CustomGpo.Name) successful" "Import_GPOs" 1
                                Log-ScriptEvent $NewReport "$($CustomGpo.Name) has guid - $($ImportedGpo.Id)" "Import_GPOs" 1
                
                            }   #End of If ($?)...

                            Else {

                                Log-ScriptEvent $NewReport "Import of $($CustomGpo.Name) failed. $($Error[0].exception.message)" "Import_GPOs" 3             

                            }   #End of Else ($?)...


                    }   #End of If (Test-Path -Path $MigrationFile)...

                    Else {
                    
                        #Record that the migration table isn't present and exit
                        Log-ScriptEvent $NewReport "$MigrationFile not found. " "Import_GPOs" 3
                        Log-ScriptEvent $NewReport "Script execution stopped" "Import_GPOs" 1
                        Log-ScriptEvent $NewReport ("=" * 90) "Import_GPOs" 1
                        Write-Error "$MigrationFile not found. Script execution stopped."
                        Exit 3


                    }   #End of Else (Test-Path -Path $MigrationFile)...


                }   #End of If ($MigTable)...

                Else {

                    #Import all the GPOs referenced in the backup folder
                    $ImportedGpo = Import-GPO -BackupId $CustomGpo.BackupGuid `                                              -Path $BackupFolder `
                                              -CreateIfNeeded `                                              -Domain $TargetDomainFQDN `                                              -TargetName $CustomGpo.Name `
                                              -Server $TargetPDC `
                                              -ErrorAction SilentlyContinue


                        #Log the outcome of $ImportedGpo
                        If ($?) {

                            Log-ScriptEvent $NewReport "Import of $($CustomGpo.Name) successful" "Import_GPOs" 1
                            Log-ScriptEvent $NewReport "$($CustomGpo.Name) has guid - $($ImportedGpo.Id)" "Import_GPOs" 1
                
                        }   #End of If ($?)...

                        Else {

                            Log-ScriptEvent $NewReport "Import of $($CustomGpo.Name) failed. $($Error[0].exception.message)" "Import_GPOs" 3             

                        }   #End of Else ($?)...


                }   #End of Else ($MigTable)...



                ################################
                ###Section 3 - Link WMI filters
                ##Link previously updated WMI filters to GPOs (Update_WMI)
                #Check whether the a -WmiFilter switch was supplied at function execution
                If ($WmiFilter) {

                    #Check whether the current GPO custom object has a WMI filter associated
                    If ($CustomGpo.WmiFilter) {

                        #Log filter found
                        Log-ScriptEvent $NewReport "Found filter entry: $($CustomGpo.WmiFilter)" "Update_WMI" 1


                        ##Check that the associated filter exists in the target doamin
                        #Contruct the target WMI DN
                        $TargetWmiDN = "CN=$($CustomGpo.WmiFilter),CN=SOM,CN=WMIPolicy,CN=System,$TargetDomainDN"

                        #Test that the WMI filter exists
                        $TargetWMI = Get-ADObject -Identity $TargetWmiDN -Property "msWMI-Name" -Server $TargetPDC -ErrorAction SilentlyContinue


                        #If the object already exists then link it to the current GPO
                        If ($TargetWMI) {

                            #Log that WMI object exists
                            Log-ScriptEvent $NewReport "`"$($TargetWMI."msWMI-Name") - $($TargetWMI.Name)`" WMI filter already exists in $Domain" "Update_WMI" 1


                            ##We'll have to update an attribute on the GPO object in AD
                            #Contruct the target GPO DN
                            $TargetGpoDN = "CN={$($ImportedGpo.Id)},CN=Policies,CN=System,$TargetDomainDN"

                            #Update the GPO attribute in AD
                            $UpdateGpoFilter = Set-ADObject $TargetGpoDN -Replace @{gPCWQLFilter = "[$TargetDomainFQDN;$($TargetWMI.Name);0]"} -Server $TargetPDC -ErrorAction SilentlyContinue


                                #Check the success of the Set-ADObject cmdlet
                                If ($?) {

                                    #Log success of Set-ADObject cmdlet
                                    Log-ScriptEvent $NewReport "Link of `"$($TargetWMI."msWMI-Name") - $($TargetWMI.Name)`" to $TargetGpoDN succeeded." "Update_WMI" 1   


                                }   #End of If ($?)

                                Else {

                                    #Log failure of Set-ADObject cmdlet
                                    Log-ScriptEvent $NewReport "Link of `"$($TargetWMI."msWMI-Name") - $($TargetWMI.Name)`" to $TargetGpoDN failed. $($Error[0].exception.message)" "Update_WMI" 3   


                                }   #End of Else (?)


                        }   #End of If ($TargetWMI)

                        Else {

                            #Log that WMI object does not exist
                            Log-ScriptEvent $NewReport "`"$($TargetWMI."msWMI-Name") - $($TargetWMI.Name)`" WMI filter does not exist in $Domain" "Update_WMI" 3


                        }   #End of Else ($TargetWMI)
                        

                    }   #End of If ($CustomGpo.WmiFilter)


                }   #End of If ($WmiFilter) 



                ###############################
                ###Section 4 - Create GPO links
                ##Creating the necessary GPO links is a two part process.. part one ensures that the GPO links are present (Create_Links)
                #Check whether the -SomInfo switch was supplied at function execution
                If ($SomInfo) {


                    #Check whether the GPO has any SOM information
                    If ($CustomGpo.SOMs) {
                    
                        #Get a list of any associated SOMs
                        $SOMs = $CustomGpo | Select-Object -ExpandProperty SOMs


                        #Log SOMs found
                        Log-ScriptEvent $NewReport "Found SOM entries: $SOMs" "Create_Links" 1


                        #Loop through each SOM and associate it with a target
                        ForEach ($SOM in $SOMs) {

                            #Get the DN part from the SOM entry
                            $SomDN = ($SOM –Split ":")[0] 


                            #Replace the domain DNs
                            $SomDN = $SomDN –Replace $SourceDomainDN, $TargetDomainDN

                        
                            #Log SOM DN update
                            Log-ScriptEvent $NewReport "SOM DN set as $SomDN" "Create_Links" 1


                            #Check the SOM target exists
                            $TargetSom = Get-ADObject -Identity $SomDn -Server $TargetPDC -ErrorAction SilentlyContinue

                            If ($?) {

                                #Log confirmation of SOM target
                                Log-ScriptEvent $NewReport "$SomDn exists in target domain" "Create_Links" 1


                                #Create a corresponding SOM link
                                $SomLink = New-GPLink -Guid $ImportedGpo.Id -Domain $TargetDomainFQDN -Target $SomDN -Server $TargetPDC -ErrorAction SilentlyContinue


                                    #Log the outcome of $SomLink
                                    If ($?) {

                                        Log-ScriptEvent $NewReport "GPO Link created for $($ImportedGPO.Id) at $SomDn" "Create_Links" 1
                
                                    }   #End of If ($?)...

                                    Else {

                                        Log-ScriptEvent $NewReport "Creation of GPO link at $SomDn failed. $($Error[0].exception.message)" "Create_Links" 3             

                                    }   #End of Else ($?)...


                            }   #End of If ($?) ($TargetSom)...

                            Else {

                                #Log failure to verify SOM target
                                Log-ScriptEvent $NewReport "$SomDn does not exist in target domain" "Create_Links" 3


                            }   #End of Else ($?)...


                        }   #End of ForEach ($SOM in $SOMs)...


                    }   #End of If ($CustomGpo.SOMs)...

                    #Add the GPO guid from the new domain to our custom GPO information
                    $CustomGpo | Add-Member -MemberType NoteProperty -Name NewGpoGuid -Value $ImportedGpo.Id


                }   #End of If ($SomInfo)...

                #Spin up a progress bar for each GPO processed
                Write-Progress -activity "Importing Group Policies to $TargetDomainFQDN" -status "Processed: $i" -percentcomplete -1


                #Increment the GPO processed counter
                $i++


            }   #End of ForEach ($CustomGpo in $CustomGpoInfo)...



            ##################################
            ###Section 5 - Configure GPO Links
            ##This is part two of the SOM / GPO link creation process (Update_Links)
            #Check whether the -SomInfo switch was supplied at function execution
            If ($SomInfo) {

                #A counter for each GPO linked
                $j = 0

 
                #We need to loop through $CustomGPOInfo again and set enabled status and precendence on GPO links
                ForEach ($CustomGpo in $CustomGpoInfo) {           

                    #Check whether the GPO has any SOM information
                    If ($CustomGpo.SOMs) {

                    #Log current GPO name
                    Log-ScriptEvent $NewReport " " " " 1
                    Log-ScriptEvent $NewReport "Processing GPO link updates for $($CustomGpo.Name)..." "Update_Links" 1
            

                        #Get a list of any associated SOMs
                        $SOMs = $CustomGpo | Select -ExpandProperty SOMs


                        #Loop through each SOM and associate it with a target
                        ForEach ($SOM in $SOMs) {

                            #Get the DN part from the SOM entry
                            $SomDN = ($SOM -Split ":")[0]


                            #Replace the domain DNs
                            $SomDN = $SomDN –Replace $SourceDomainDN, $TargetDomainDN


                            #Check the SOM target exists
                            $TargetSom = Get-ADObject -Identity $SomDn -Server $TargetPDC -ErrorAction SilentlyContinue

                            If ($?) {

                                #Determine the GPO link status of the SOM entry
                                Switch ($SOM.Split(":")[2]) {

                                    $True {

                                        #Set the GPO link enabled variable to Yes
                                        $LinkEnabled = "Yes"


                                    }   #End of $True

                                    $False {

                                        #Set the GPO link enabled variable to No
                                        $LinkEnabled = "No"

                                    }   #End of $False

                                }   #End of Switch ($SOM.Split(":")[2])


                                #Get the GPO link order part of the SOM entry
                                $LinkOrder = $SOM.Split(":")[3]


                                    #Determine the GPO enforced status of the SOM entry
                                    Switch ($SOM.Split(":")[4]) {

                                        $True {

                                            #Set the GPO link enabled variable to Yes
                                            $LinkEnforced = "Yes"


                                        }   #End of $True

                                        $False {

                                            #Set the GPO link enabled variable to No
                                            $LinkEnforced = "No"

                                        }   #End of $False

                                    }   #End of Switch ($SOM.Split(":")[4])


                                #The SOM link has already been created, so now set the 'enabled', 'order' and 'enforced' properties
                                $SomLink = Set-GPLink -Guid $CustomGpo.NewGpoGuid `                                                      -Domain $TargetDomainFQDN `                                                      -Target $SomDN `                                                      -LinkEnabled $LinkEnabled `                                                      -Order $LinkOrder `                                                      -Enforced $LinkEnforced `
                                                      -Server $TargetPDC `
                                                      -ErrorAction SilentlyContinue


                                #Log the outcome of $SomLink
                                If ($?) {
                                
                                    #Log $SomLink success details
                                    Log-ScriptEvent $NewReport "GPO link updated for $($ImportedGPO.Id) at $SomDn" "Update_Links" 1
                                
                                    #Log an Enforced entry as a warning (severity 2)
                                    If ($LinkEnforced -eq "Yes") {

                                        #Log with severity 2
                                        Log-ScriptEvent $NewReport "GPO link set to `"Enabled: $LinkEnabled`" `"Order: $LinkOrder`" `"ENFORCED: $($LinkEnforced.ToUpper())`"" "Update_Links" 2

                                    }   #End of If ($LinkEnforced -eq "Yes")

                                    Else {

                                        #Log with severity 1
                                        Log-ScriptEvent $NewReport "GPO link set to `"Enabled: $LinkEnabled`" `"Order: $LinkOrder`" `"Enforced: $LinkEnforced`"" "Update_Links" 1


                                    }   #End of Else ($LinkEnforced -eq "Yes")

                                
                                    #Increment the GPO linked counter
                                    $j++

                
                                }   #End of If ($?) ($SomLink)...

                                Else {

                                    #Log $SomLink failure details
                                    Log-ScriptEvent $NewReport "Creation of GPO link at $SomDn failed. $($Error[0].exception.message)" "Update_Links" 3             

                                }   #End of Else ($?) ($SomLink)...


                                #Get the block inheritance part of the SOM entry
                                $SomInheritance = $SOM.Split(":")[1]


                                #Check if we need should set Block Inheritance
                                If ($SomInheritance -eq $True) {

                                    #Set block inheritance
                                    $SetInheritance = Set-GPInheritance -Target $SomDn -IsBlocked Yes -Server $TargetPDC -ErrorAction SilentlyContinue

                                    If ($?) {

                                    #Log failure to set block inheritance
                                    Log-ScriptEvent $NewReport "BLOCK INHERITANCE set on $SomDn" "Update_Links" 2
                                    

                                    }   #End of If ($?) ($SetInheritance)...

                                    Else {

                                        #Log failure to set block inheritance
                                        Log-ScriptEvent $NewReport "Can not set Block Inheritance on $SomDn" "Update_Links" 3


                                    }   #End of Else ($?) ($SetInheritance)...
                                 

                                }   #End of If ($SomInheritance -eq $True)...


                            }   # End of If ($?) ($TargetSom)...

                            Else {

                                #Log failure to verify SOM target
                                Log-ScriptEvent $NewReport "$SomDn does not exist in target domain" "Update_Links" 3


                            }   # End of Else ($?) ($TargetSom)...


                        }   #End of ForEach ($SOM in $SOMs)...


                    }   #End of If ($CustomGpo.SOMs)


                #Spin up a progress bar for each GPO processed
                Write-Progress -activity "Linking Group Policies to $TargetDomainFQDN" -status "Processed: $j" -percentcomplete -1


                }   #End of ForEach ($CustomGpo in $CustomGpoInfo)...


            }   #End of If ($SomInfo)...


        }   #End of If ($CustomGpoInfo)...

        Else {

        #Log failure to import custom GPO XML object
        Log-ScriptEvent $NewReport "$CustomGpoXML import failed" "Import_GPOs" 3
        Log-ScriptEvent $NewReport "Script execution stopped" "Import_GPOs" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Import_GPOs" 1
        Write-Error "$CustomGpoXML not found. Script execution stopped."
        Exit 2

        }   #End of Else ($CustomGpoInfo)...

        ##Finish Script (Finish_Script)
        #Close of the script log
        Log-ScriptEvent $NewReport " " " " 1 
        Log-ScriptEvent $NewReport ("=" * 90) "Finish_Script" 1
        Log-ScriptEvent $NewReport "FILTERS_IMPORTED: $k" "Finish_Script" 1
        Log-ScriptEvent $NewReport "POLICIES_PROCESSED: $i" "Finish_Script" 1
        Log-ScriptEvent $NewReport "LINKS_UPDATED: $j" "Finish_Script" 1
        Log-ScriptEvent $NewReport ("=" * 90) "Finish_Script" 1


    }   #End of If (New-Item -ItemType File -Path $NewReport)...

    Else {

        #Write a custom error and use continue to override silently continue
        Write-Error "$NewReport not found. Script execution stopped."
        Exit 1

    }   #End of Else (New-Item -ItemType File -Path $NewReport)...

}   #end of function Mirror-ADGpos
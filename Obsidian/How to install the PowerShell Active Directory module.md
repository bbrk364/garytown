Contents

1.  [Windows 7](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#windows-7)
2.  [Windows Server 2008 R2](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#windows-server-2008-r2)
3.  [Windows 8, Windows 8.1](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#windows-8-windows-81)
4.  [Windows 10](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#windows-10)
5.  [Windows 11](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#windows-11)
6.  [On Windows 11 with PowerShell](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#on-windows-11-with-powershell)
7.  [Windows Server 2012, Windows Server 2012 R2, Windows Server 2016, Windows Server 2019, Windows Server 2022](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#windows-server-2012-windows-server-2012-r2-windows-server-2016-windows-server-2019-windows-server-2022)
8.  [Install the AD module on PowerShell Core 6.x on a Windows computer](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#install-the-ad-module-on-powershell-core-6x-on-a-windows-computer)
9.  [Use the Active Directory module on Linux and macOS](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#use-the-active-directory-module-on-linux-and-macos)
10.  [All versions: Import the ActiveDirectory module remotely](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#all-versions-import-the-activedirectory-module-remotely)
11.  [PowerShell Core and Windows PowerShell modules](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#powershell-core-and-windows-powershell-modules)
12.  [Conclusion](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#conclusion)

Also read: [How to install the PowerShell 7 Active Directory module](https://4sysops.com/archives/how-to-install-the-powershell-7-active-directory-module/).

The installation of the AD module varies significantly for the different Windows and PowerShell versions. At the time of this writing, the AD module that comes with RAST does not work with PowerShell Core 6.0. However, this guide explains how you can manage Active Directory from PowerShell Core even on macOS and Linux.  

## Windows 7 [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

On a Windows 7 computer, you can follow this procedure to install the Active Directory module:

1.  [Download](http://www.microsoft.com/en-us/download/details.aspx?id=7887) the Remote Server Administration Tools (RSAT) for Windows 7.
2.  Open the **Control Panel**, start typing _features_, and then click _Turn Windows features on or off_.
3.  Scroll down to _Remote Server Administration Tools_ and enable the **Active Directory Module for Windows PowerShell** in **Remote Server Administration Tools > Role Administration Tools > AD DS and AD LDS Tools**.
4.  Run _Import-Module ActiveDirectory_ on a PowerShell console.

[![Active Directory Module for Windows PowerShell on Windows 7](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Active-Directory-Module-for-Windows-PowerShell-on-Windows-7-600x406.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Active-Directory-Module-for-Windows-PowerShell-on-Windows-7.png)

Active Directory Module for Windows PowerShell on Windows 7

If the Windows 7 machine only has PowerShell 2.0 installed, you have to add the _Import-Module ActiveDirectory_ command to your [profile](https://4sysops.com/archives/the-powershell-profile/) because PowerShell doesn't load modules automatically. For instance, you can import the module in _%UserProfile%\My Documents\WindowsPowerShell\profile.ps1_. Makes sure you've set your execution policy to either _RemoteSigned_ or _Unrestricted_: _Set-ExecutionPolicy RemoteSigned_.

Another option is to open the module from the _Administrative Tools_ folder in the Control Panel.

[![Active Directory Module in Administrative Tools](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Active-Directory-Module-in-Administrative-Tools-600x362.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Active-Directory-Module-in-Administrative-Tools.png)

Active Directory Module in Administrative Tools

## Windows Server 2008 R2 [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

If your Windows Server 2008 R2 machine is a domain controller, the PowerShell Active Directory Module is already installed. You only have to install the module on member servers. The procedure on Windows Server 2008 R2 is similar to that on Windows 7. (Note that the module is not available for Windows Server 2008.)

One difference is that you don't have to download RSAT because the tools are already available on Windows Server 2008 R2.

1.  In **Server Manager**, click **Add features**, and then:
2.  Select **Active Directory module for Windows PowerShell** in **Remote Server Administration Tools > Role Administration Tools > AD DS and AD LDS Tools**.

Alternatively, you can install the module from a PowerShell console:

Import-Module ServerManagerAdd-WindowsFeature RSAT-AD-PowerShell

After copying the module to your computer, you have to import it:

Import-Module ActiveDirectory

Or you can right-click the PowerShell icon on the taskbar and select **Import system modules**.

[![Import system modules](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Import-system-modules.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Import-system-modules.png)

Import system modules

As on Windows 7, if you want to make the import permanent, you have to add the above import command to your PowerShell profile. Notice this description assumes you haven't updated PowerShell 2 on your Windows Server 2008 R2 machine (see the description about Windows 7).

## Windows 8, Windows 8.1 [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

Things are a lot easier in Windows 8, Windows 8.1, and Windows 10. All you have to do is download and install RSAT ([Windows 8](http://www.microsoft.com/en-us/download/details.aspx?id=28972), [Windows 8.1](http://www.microsoft.com/en-us/download/details.aspx?id=39296), [Windows 10](https://www.microsoft.com/en-us/download/details.aspx?id=45520)). The installation enables all tools by default, and you also don't have to import the module. You can use the AD module right away after you install RSAT.

## Windows 10 [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

Since Windows 10, the RSAT tools were shifted from being a standalone package to being a feature on demand in Windows 10. Click the menu and then search for "features" and then navigate to **App and Features > Optional Features > Add a feature**. Type RSAT in the search field and select the second option—RSAT: Active Directory Domain Services and Lightweight Directory Services Tools.

[![Install the AD module in Windows 10](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Install-the-AD-module-in-Windows-10-600x642.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Install-the-AD-module-in-Windows-10.png)

Install the AD module in Windows 10

## Windows 11 [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

In Windows 11, click the **Start**, type "**Settings**" in the Search field.

[![Apps in Windows 11](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Apps-in-Windows-11-600x472.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Apps-in-Windows-11.png)

Apps in Windows 11

Now click **Apps > Optional Features > View features**.

[![Optinal Features in Windows 11](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Optinal-Features-in-Windows-11-600x475.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Optinal-Features-in-Windows-11.png)

Optinal Features in Windows 11

[![Add an optional feature in Windows 11](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Add-an-optional-feature-in-Windows-11-600x473.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Add-an-optional-feature-in-Windows-11.png)

Add an optional feature in Windows 11

Then type "RSAT" and select **RSAT: Active Directory Domain Services and Lightweight Directory Services Tools** and click **Next** and then **Install.**

[![Install RSAT on Windows 11](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Install-RSAT-on-Windows-11-600x472.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Install-RSAT-on-Windows-11.png)

Install RSAT on Windows 11

To verify that RSAT has been installed launch a PowerShell console with Administrator privileges and then type this command:

Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State

[![Verfiying that RSAT is installed with PowerShell](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Verfiying-that-RSAT-is-installed-with-PowerShell-600x311.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Verfiying-that-RSAT-is-installed-with-PowerShell.png)

Verfiying that RSAT is installed with PowerShell

## On Windows 11 with PowerShell [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

If you don't want to avoid all this clicking you can install all the RSAT tools in one go with this PowerShell command below. Make sure that you are working on an elevated PowerShell console.

Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

[![Intstall RSAT with PowerShell](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Intstall-RSAT-with-PowerShell-600x311.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Intstall-RSAT-with-PowerShell.png)

Intstall RSAT with PowerShell

## Windows Server 2012, Windows Server 2012 R2, Windows Server 2016, Windows Server 2019, Windows Server 2022 [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

As on Windows Server 2008 R2, the AD module is already installed on domain controllers on Windows Server 2012, Windows Server 2012 R2, and Windows Server 2016. On member servers, you can add the module as a feature in Server Manager.

1.  Start **Server Manager**.
2.  Click **Manage > Add Roles and Features**.
3.  Click **Next** until you reach **Features**.
4.  Enable **Active Directory module for Windows PowerShell** in **Remote Server Administration Tools > Role Administration Tools > AD DS and AD LDS Tools**.

[![Install the AD module on Windows Server 2016](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Install-the-AD-module-on-Windows-Server-2016-600x420.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Install-the-AD-module-on-Windows-Server-2016.png)

Install the AD module on Windows Server 2016

Alternatively, you can install the module from a PowerShell console:

Install-WindowsFeature RSAT-AD-PowerShell

[![Installing the AD module on Windows Server 2012 with PowerShell](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Installing-the-AD-module-on-Windows-Server-2012-with-PowerShell-600x231.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Installing-the-AD-module-on-Windows-Server-2012-with-PowerShell.png)

Installing the AD module on Windows Server 2012 with PowerShell

There's no need to import the Server Manager module first, as on Windows Server 2008 R2. You also don't have to import the AD module after the installation.

If you want to verify the successful installation of the module, you can just run the _Get-ADuser_ cmdlet.

## Install the AD module on PowerShell Core 6.x on a Windows computer [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

1.  Install RSAT with the method matching to your operating system (see sections above).
2.  Install the **WindowsCompatibility** module.
    
    Install-Module -Name WindowsCompatibility
    
3.  Load the **WindowsCompatibility** module like usual with the **Import-Module** cmdlet
    
    Import-Module -Name WindowsCompatibility
    
4.  Load the **ActiveDirectory** module with the **Import-WinModule** cmdlet
    
    Import-WinModule -Name ActiveDirectory
    

## Use the Active Directory module on Linux and macOS [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

On Linux and macOS you can't install Active Directory module. However, you use [PowerShell remoting](https://4sysops.com/groups/powershell/wiki/?folder=340503) to connect to a Windows server with Active Directory and then work with the AD module in remoting session. Read ahead to learn how to use remoting with the AD module.

## All versions: Import the ActiveDirectory module remotely [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

### Create an interactive remote session

The simplest option is to create an interactive remote session to your domain controller with the _Enter-PSsession_ cmdlet:

Enter-PSsession MyDomainConroller

You can then work right away with the AD cmdlets. This option is good if you only occasionally manage AD on a PowerShell console and if you don't have to execute local scripts.

[![Managing Active Directory on PowerShell Core in an interactive remote session](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Managing-Active-Directory-on-PowerShell-Core-in-an-interactive-remote-session-600x229.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Managing-Active-Directory-on-PowerShell-Core-in-an-interactive-remote-session.png)

Managing Active Directory on PowerShell Core in an interactive remote session

### Import the AD module from a remote session

The second option uses implicit remoting and allows you to run the AD cmdlets from a local session. However, you execute the AD cmdlets remotely on a domain controller. In practice, you won't notice much of difference in locally installed cmdlets. To import the AD module on PowerShell Core 6.0, execute these commands:

$S = New-PSSession -ComputerName MyDomainConroller

Import-Module -PSsession $S -Name ActiveDirectory

[![Import the AD module on PowerShell Core 6.0](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Import-the-AD-module-on-PowerShell-Core-6.0-600x214.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Import-the-AD-module-on-PowerShell-Core-6.0.png)

Import the AD module on PowerShell Core 6.0

The first command creates a PowerShell session (_PSsession_) on the domain controller (replace _MyDomainController_ with the name of your DC) and establishes a persistent connection. Next, we import the _ActiveDirectory_ module from this remote _PSsession_ into our local session.

You can now use all AD module cmdlets on your local PowerShell Core console. Just keep in mind the commands always execute remotely.

If you often work with AD, you can add the above commands to your profile, for instance in _Documents\PowerShell\Profile.ps1_.

### Export the remote AD module to a local module

Alternatively, you can export the AD cmdlets from a remote session to a local module:

$S = New-PSSession -ComputerName MyDomainController

Export-PSsession -Session $S -Module ActiveDirectory -OutputModule RemoteAD

Remove-PSSession -Session $S

Import-Module RemoteAD

[![Exporting the Active Directory module to a local module](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Exporting-the-Active-Directory-module-to-a-local-module-600x336.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/Exporting-the-Active-Directory-module-to-a-local-module.png)

Exporting the Active Directory module to a local module

These commands will create a local module in your _Documents_ folder under _PowerShell\Modules\RemoteAD_. However, like with the above solution, you will be working with implicit remoting, and all cmdlets will execute remotely. The local _RemoteAD_ module only links to the cmdlets on the domain controller. If you want to use the _RemoteAD_ module on other machines with PowerShell Core, simply copy the RemoteAD folder to the PowerShell Core module folder on the second machine.

The difference with the "import solution" is that in the "export solution," PowerShell only establishes a connection to the domain controller when you use an AD cmdlet the first time. You also don't have to add the above commands to your profile because PowerShell will load the local _RemoteAD_ module automatically. However, the downside to this option is you might have to repeat the procedure after updating the AD module on the domain controller.

## PowerShell Core and Windows PowerShell modules [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

Note that you can use Windows PowerShell together with PowerShell Core on the same machine and work with the different AD modules in both shells. If you installed RSAT, the AD module for Windows PowerShell will reside in this folder:

_$env:windir/System32/WindowsPowerShell/v1.0/Modules/ActiveDirectory_

If you used the export solution, the RemoteAD module will be in this folder:

_$env:userprofile/Documents/PowerShell/Modules/RemoteAD_

[![PowerShell Core and Windows PowerShell use different folders](https://4sysops.com/wp-content/uploads/bp-attachments/449877/PowerShell-Core-and-Windows-PowerShell-use-different-folders-600x360.png)](https://4sysops.com/wp-content/uploads/bp-attachments/449877/PowerShell-Core-and-Windows-PowerShell-use-different-folders.png)

PowerShell Core and Windows PowerShell use different folders

PowerShell Core does not import modules in _WindowsPowerShell_ folders, and Windows PowerShell does not load PowerShell Core modules, which are always in _PowerShell_ folders. Thus, you don't have to worry about conflicts between the different AD modules in PowerShell Core and Windows PowerShell.

## Conclusion [^](https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/#Content-bal-title "Back to table of contents")

Using the Active Directory module has become simpler with each PowerShell version up to Microsoft's release of PowerShell Core 6.0. However, working with implicit remoting and remote sessions has various advantages. One advantage is that you can use [disconnected remote sessions](https://4sysops.com/archives/powershell-disconnected-remote-sessions/). This allows you to start a script, shut down your client computer, and retrieve the results from the remote machine later. If you often work with remote sessions, you should become familiar with the [different ways you can use PowerShell remote sessions](https://4sysops.com/archives/powershell-remote-jobs-indisconnectedsession-asjob-and-start-job/). Once you get used to working with remoting, you probably won't miss the local AD module for PowerShell Core.
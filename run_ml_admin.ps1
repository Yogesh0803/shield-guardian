Set-Location "C:\Users\hp\Desktop\COLLEGE 1\Capgemini\guardian-shield"
python -m ml.main --simulate 2>&1 | Tee-Object -FilePath "ml_engine.log"
Read-Host "Press Enter to exit"

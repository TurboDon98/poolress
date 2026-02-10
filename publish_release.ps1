# Скрипт для автоматической сборки и публикации релиза на GitHub

# 1. Настройка окружения
$env:GH_TOKEN = $env:GH_TOKEN_INPUT # Предполагается, что токен задан в переменной окружения или будет введен пользователем
if (-not $env:GH_TOKEN) {
    Write-Host "Внимание: GH_TOKEN не задан. Публикация может не сработать." -ForegroundColor Yellow
}
$env:ELECTRON_MIRROR = "https://npmmirror.com/mirrors/electron/"

# 2. Переход в папку frontend
Set-Location "frontend"

# 3. Чтение текущей версии из package.json
$packageJson = Get-Content package.json | ConvertFrom-Json
$currentVersion = $packageJson.version

Write-Host "Текущая версия: $currentVersion" -ForegroundColor Cyan
Write-Host "Начинаем сборку и публикацию..." -ForegroundColor Yellow

# 4. Запуск сборки и публикации
npm run electron:build -- --publish always

if ($LASTEXITCODE -eq 0) {
    Write-Host "УСПЕХ! Релиз v$currentVersion опубликован на GitHub." -ForegroundColor Green
} else {
    Write-Host "ОШИБКА при сборке или публикации." -ForegroundColor Red
}

# 5. Возврат в корень
Set-Location ..

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { autoUpdater } = require('electron-updater');

// Configure autoUpdater
autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = true;

let mainWindow = null;

const createWindow = () => {
  // Create the browser window.
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 768,
    frame: true, // Native frame for now, can be custom later
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
    },
    title: 'TurboProject 2.0',
    backgroundColor: '#09090b', // zinc-950
    show: false, // Don't show until ready-to-show
    autoHideMenuBar: true, // Hide menu bar
  });

  // Remove the menu bar completely
  mainWindow.setMenu(null);

  // Load the index.html of the app.
  // Use !app.isPackaged to detect development mode reliably
  if (!app.isPackaged) {
    mainWindow.loadURL('http://localhost:5205');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
    // Check for updates only in production
    if (app.isPackaged) {
        autoUpdater.checkForUpdates();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
};

app.on('ready', createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});

// IPC handlers can go here
ipcMain.handle('app:version', () => app.getVersion());

// Auto-updater events
autoUpdater.on('update-available', (info) => {
  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'Доступно обновление',
    message: `Найден новый версия ${info.version}. Хотите установить его сейчас?`,
    buttons: ['Установить', 'Позже'],
    defaultId: 0,
    cancelId: 1
  }).then(result => {
    if (result.response === 0) {
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'Загрузка',
        message: 'Обновление загружается в фоне. Мы сообщим, когда оно будет готово к установке.',
        buttons: ['OK']
      });
      autoUpdater.downloadUpdate();
    }
  });
});

autoUpdater.on('update-downloaded', () => {
  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'Обновление готово',
    message: 'Обновление загружено. Приложение будет перезапущено для установки.',
    buttons: ['Перезапустить и установить']
  }).then(() => {
    autoUpdater.quitAndInstall(false, true);
  });
});

autoUpdater.on('error', (err) => {
  console.error('Update error:', err);
  dialog.showErrorBox('Ошибка обновления', 'Не удалось загрузить обновление: ' + (err.message || err.toString()));
});

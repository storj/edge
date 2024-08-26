// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

const pdfType = 'pdf'
const zipType = 'zip'
const spreadsheetTypes = ['xls', 'numbers', 'csv', 'xlsx', 'tsv']
const textTypes = ['txt', 'docx', 'doc', 'pages', 'md']
const imageTypes = ['bmp', 'svg', 'jpg', 'jpeg', 'png', 'ico', 'gif', 'webp']
const videoTypes = ['m4v', 'mp4', 'webm', 'mov', 'mkv', 'ogv', 'avi']
const audioTypes = ['m4a', 'mp3', 'wav', 'ogg', 'aac', 'flac', 'aif', 'aiff']

function getFileIcon(extension) {
    switch (true) {
    case extension === pdfType:
        return 'pdf.svg'
    case extension === zipType:
        return 'zip.svg'
    case spreadsheetTypes.includes(extension):
        return 'spreadsheet.svg'
    case textTypes.includes(extension):
        return 'text.svg'
    case imageTypes.includes(extension):
        return 'image.svg'
    case videoTypes.includes(extension):
        return 'video.svg'
    case audioTypes.includes(extension):
        return 'audio.svg'
    default:
        return 'placeholder.svg'
    }
}

function setFileIconSource(base, version, key, extension) {
    if (!extension) {
        extension = key.split('.').pop();
        if (extension) extension = extension.toLowerCase();
    }

    const icon = document.getElementById(`file-${key}`);
    if (icon) icon.src = `${base}/static/img/fileTypes/${getFileIcon(extension)}?v=${version}`;
}

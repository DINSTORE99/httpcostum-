const fileInput =
  document.getElementById(
    "fileInput"
  );

const upload =
  document.getElementById(
    "upload"
  );

const selectFile =
  document.getElementById(
    "selectFile"
  );

const fileInfo =
  document.getElementById(
    "fileInfo"
  );

const fileName =
  document.getElementById(
    "fileName"
  );

const fileSize =
  document.getElementById(
    "fileSize"
  );

const removeFile =
  document.getElementById(
    "removeFile"
  );

const uploadBtn =
  document.getElementById(
    "uploadBtn"
  );

const message =
  document.getElementById(
    "message"
  );


let selectedFile = null;


//// ========================================================
//// PILIH FILE
//// ========================================================

selectFile.onclick = e => {

  e.stopPropagation();

  fileInput.click();

};


upload.onclick = () => {

  fileInput.click();

};


fileInput.onchange = () => {

  if (
    fileInput.files.length
  ) {

    setFile(
      fileInput.files[0]
    );

  }

};


//// ========================================================
//// DRAG DROP
//// ========================================================

upload.ondragover = e => {

  e.preventDefault();

  upload.classList.add(
    "drag"
  );

};


upload.ondragleave = () => {

  upload.classList.remove(
    "drag"
  );

};


upload.ondrop = e => {

  e.preventDefault();

  upload.classList.remove(
    "drag"
  );

  if (
    e.dataTransfer.files.length
  ) {

    setFile(
      e.dataTransfer.files[0]
    );

  }

};


//// ========================================================
//// SET FILE
//// ========================================================

function setFile(file) {

  selectedFile = file;

  fileName.textContent =
    file.name;

  fileSize.textContent =
    formatSize(
      file.size
    );

  fileInfo.hidden =
    false;

  uploadBtn.disabled =
    false;

  message.textContent =
    "File siap diupload.";

}


//// ========================================================
//// REMOVE
//// ========================================================

removeFile.onclick = () => {

  selectedFile = null;

  fileInput.value = "";

  fileInfo.hidden =
    true;

  uploadBtn.disabled =
    true;

  message.textContent =
    "";

};


//// ========================================================
//// UPLOAD
//// ========================================================

uploadBtn.onclick =
  async () => {

    if (!selectedFile)
      return;

    uploadBtn.disabled =
      true;

    uploadBtn.textContent =
      "Uploading...";

    message.textContent =
      "Mengupload file...";


    try {

      const formData =
        new FormData();

      formData.append(
        "file",
        selectedFile
      );


      const response =
        await fetch(
          "/api/upload",
          {
            method: "POST",
            body: formData
          }
        );


      const data =
        await response.json();


      if (!response.ok) {

        throw new Error(
          data.error ||
          "Upload gagal"
        );

      }


      message.textContent =
        `Upload berhasil: ${data.file.name}`;

    } catch (error) {

      message.textContent =
        error.message;

    }


    uploadBtn.disabled =
      false;

    uploadBtn.textContent =
      "Upload File";

  };


//// ========================================================
//// FORMAT SIZE
//// ========================================================

function formatSize(bytes) {

  if (
    bytes < 1024
  ) {

    return bytes + " B";

  }

  if (
    bytes < 1024 * 1024
  ) {

    return (
      (bytes / 1024)
        .toFixed(2) +
      " KB"
    );

  }

  return (
    (bytes / 1024 / 1024)
      .toFixed(2) +
    " MB"
  );

}

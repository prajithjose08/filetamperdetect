/**
 * script.js — File Tampering Detector
 *
 * Handles:
 *  1. Sidebar hamburger toggle (mobile)
 *  2. Drag-and-drop / click file selection UI
 *  3. File size formatter helper
 *  4. Confirmation dialogs before destructive actions
 *  5. Auto-dismiss flash messages after 6 seconds
 *  6. Hash cell full-text tooltip on click
 */

// ---------------------------------------------------------------------------
// 1. Sidebar toggle (mobile)
// ---------------------------------------------------------------------------
(function () {
  const hamburger = document.getElementById("hamburger");
  const sidebar   = document.getElementById("sidebar");
  if (!hamburger || !sidebar) return;

  hamburger.addEventListener("click", () => {
    sidebar.classList.toggle("open");
  });

  // Close sidebar when clicking outside on mobile
  document.addEventListener("click", (e) => {
    if (
      sidebar.classList.contains("open") &&
      !sidebar.contains(e.target) &&
      e.target !== hamburger
    ) {
      sidebar.classList.remove("open");
    }
  });
})();

// ---------------------------------------------------------------------------
// 2. Drag-and-drop / file selection UI
// ---------------------------------------------------------------------------
(function () {
  const dropZone   = document.getElementById("dropZone");
  const fileInput  = document.getElementById("fileInput");
  const filePreview = document.getElementById("filePreview");
  const previewName = document.getElementById("previewName");
  const previewSize = document.getElementById("previewSize");

  if (!dropZone || !fileInput) return;

  function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KiB", "MiB", "GiB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
  }

  function showPreview(file) {
    if (!filePreview || !previewName || !previewSize) return;
    previewName.textContent = file.name;
    previewSize.textContent = formatBytes(file.size);
    filePreview.style.display = "block";
  }

  // Click anywhere on drop zone to trigger file picker
  dropZone.addEventListener("click", (e) => {
    if (e.target !== fileInput && !e.target.classList.contains("btn")) {
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      showPreview(fileInput.files[0]);
    }
  });

  // Drag events
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drag-over");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      // Assign dropped file to the hidden input via DataTransfer
      const dt = new DataTransfer();
      dt.items.add(files[0]);
      fileInput.files = dt.files;
      showPreview(files[0]);
    }
  });
})();

// ---------------------------------------------------------------------------
// 3. Auto-dismiss flash messages after 6 seconds
// ---------------------------------------------------------------------------
(function () {
  const flashes = document.querySelectorAll(".flash");
  flashes.forEach((el) => {
    setTimeout(() => {
      el.style.transition = "opacity .5s";
      el.style.opacity = "0";
      setTimeout(() => el.remove(), 500);
    }, 6000);
  });
})();

// ---------------------------------------------------------------------------
// 4. Hash cell: click to copy full hash
// ---------------------------------------------------------------------------
(function () {
  document.querySelectorAll(".hash-cell").forEach((cell) => {
    cell.addEventListener("click", () => {
      const fullHash = cell.getAttribute("title");
      if (!fullHash) return;
      navigator.clipboard.writeText(fullHash).then(() => {
        const original = cell.textContent;
        cell.textContent = "Copied!";
        setTimeout(() => { cell.textContent = original; }, 1200);
      }).catch(() => {
        // Clipboard not available — do nothing silently
      });
    });
  });
})();

// ---------------------------------------------------------------------------
// 5. Confirm before delete form submit
// ---------------------------------------------------------------------------
(function () {
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (e) => {
      const msg = form.getAttribute("data-confirm") ||
        "Are you sure? This action cannot be undone.";
      if (!confirm(msg)) {
        e.preventDefault();
      }
    });
  });
})();

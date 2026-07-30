/*
====================================================
CyberDefense XDR
Incident Response Module
====================================================
*/

document.addEventListener("DOMContentLoaded", () => {
    initializeIncidentModule();
});

function initializeIncidentModule() {
    initializeSearch();
    initializeFilters();
    initializeTables();
    initializeModals();
    initializeToasts();
    initializeDeleteButtons();
}

/* ===========================
   Search
=========================== */

function initializeSearch() {
    const searchInput = document.querySelector("#searchInput");

    if (!searchInput) return;

    searchInput.addEventListener("keyup", function () {

        const value = this.value.toLowerCase();

        document.querySelectorAll("tbody tr").forEach(row => {

            row.style.display = row.innerText
                .toLowerCase()
                .includes(value)
                ? ""
                : "none";

        });

    });
}

/* ===========================
   Filters
=========================== */

function initializeFilters() {

    const filter = document.querySelector("#severityFilter");

    if (!filter) return;

    filter.addEventListener("change", function () {

        const value = this.value;

        document.querySelectorAll("tbody tr").forEach(row => {

            if (
                value === "all" ||
                row.dataset.severity === value
            ) {

                row.style.display = "";

            } else {

                row.style.display = "none";

            }

        });

    });

}

/* ===========================
   Tables
=========================== */

function initializeTables() {

    console.log("Incident table initialized.");

}

/* ===========================
   Delete Confirmation
=========================== */

function initializeDeleteButtons() {

    document.querySelectorAll(".delete-btn").forEach(button => {

        button.addEventListener("click", function () {

            if (confirm("Delete this incident?")) {

                alert("Incident deleted.");

            }

        });

    });

}

/* ===========================
   Bootstrap Modal
=========================== */

function initializeModals() {

    document.querySelectorAll("[data-bs-toggle='modal']").forEach(() => {

        console.log("Modal Ready");

    });

}

/* ===========================
   Toast
=========================== */

function initializeToasts() {

    const toastEl = document.querySelector(".toast");

    if (!toastEl) return;

    const toast = new bootstrap.Toast(toastEl);

    toast.show();

}

/* ===========================
   Incident Statistics
=========================== */

function updateStatistics() {

    const total = document.querySelector("#totalIncidents");

    if (total) {

        total.innerText = document.querySelectorAll("tbody tr").length;

    }

}

/* ===========================
   Timeline
=========================== */

function loadTimeline() {

    console.log("Timeline Loaded");

}

/* ===========================
   Evidence
=========================== */

function loadEvidence() {

    console.log("Evidence Loaded");

}

/* ===========================
   Playbooks
=========================== */

function loadPlaybooks() {

    console.log("Playbooks Loaded");

}

/* ===========================
   Export
=========================== */

function exportIncidents() {

    alert("Export functionality coming soon.");

}
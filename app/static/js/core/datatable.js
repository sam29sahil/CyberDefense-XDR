/* ==========================================================================
   datatable.js — one reusable table engine (search + sort + filter + paginate)
   Usage:
   new XDRTable({
     tableEl, data: [...], pageSize: 10,
     columns: [{ key:'name', label:'Name', sortable:true, render:(row)=>`...` }],
     searchKeys: ['name','ip'],
     onRowsChange: (visibleRows) => {}
   })
   ========================================================================== */

   class XDRTable {
    constructor(opts) {
      this.table = opts.tableEl;
      this.data = opts.data || [];
      this.columns = opts.columns || [];
      this.pageSize = opts.pageSize || 10;
      this.searchKeys = opts.searchKeys || [];
      this.searchInput = opts.searchInput || null;
      this.paginationEl = opts.paginationEl || null;
      this.filterFn = null; // set externally e.g. by dropdown filters
      this.state = { sortKey: null, sortDir: 1, page: 1, query: "" };
      this._buildHead();
      this._bindSearch();
      this.render();
    }
  
    _buildHead() {
      const thead = this.table.querySelector("thead tr");
      if (!thead) return;
      thead.innerHTML = this.columns.map(col => `
        <th data-key="${col.key}" class="${col.sortable ? '' : ''}">
          ${col.label}${col.sortable ? '<i class="bi bi-chevron-expand sort-icon"></i>' : ''}
        </th>`).join('');
      thead.querySelectorAll("th").forEach(th => {
        const col = this.columns.find(c => c.key === th.dataset.key);
        if (col && col.sortable) {
          th.addEventListener("click", () => this._sortBy(col.key));
        }
      });
    }
  
    _sortBy(key) {
      if (this.state.sortKey === key) {
        this.state.sortDir *= -1;
      } else {
        this.state.sortKey = key;
        this.state.sortDir = 1;
      }
      this.state.page = 1;
      this.render();
    }
  
    _bindSearch() {
      if (!this.searchInput) return;
      this.searchInput.addEventListener("input", (e) => {
        this.state.query = e.target.value.trim().toLowerCase();
        this.state.page = 1;
        this.render();
      });
    }
  
    setFilter(fn) {
      this.filterFn = fn;
      this.state.page = 1;
      this.render();
    }
  
    _getFiltered() {
      let rows = this.data.slice();
      if (this.filterFn) rows = rows.filter(this.filterFn);
      if (this.state.query) {
        const q = this.state.query;
        rows = rows.filter(row =>
          this.searchKeys.some(k => String(row[k] ?? "").toLowerCase().includes(q))
        );
      }
      if (this.state.sortKey) {
        const k = this.state.sortKey, dir = this.state.sortDir;
        rows.sort((a, b) => {
          const av = a[k], bv = b[k];
          if (av === bv) return 0;
          return (av > bv ? 1 : -1) * dir;
        });
      }
      return rows;
    }
  
    render() {
      const filtered = this._getFiltered();
      const totalPages = Math.max(1, Math.ceil(filtered.length / this.pageSize));
      if (this.state.page > totalPages) this.state.page = totalPages;
      const start = (this.state.page - 1) * this.pageSize;
      const pageRows = filtered.slice(start, start + this.pageSize);
  
      const thead = this.table.querySelector("thead tr");
      if (thead) {
        thead.querySelectorAll("th").forEach(th => {
          th.classList.toggle("sorted", th.dataset.key === this.state.sortKey);
          const icon = th.querySelector(".sort-icon");
          if (icon && th.dataset.key === this.state.sortKey) {
            icon.className = `bi ${this.state.sortDir === 1 ? 'bi-chevron-up' : 'bi-chevron-down'} sort-icon`;
          } else if (icon) {
            icon.className = "bi bi-chevron-expand sort-icon";
          }
        });
      }
  
      const tbody = this.table.querySelector("tbody");
      if (tbody) {
        if (pageRows.length === 0) {
          tbody.innerHTML = `<tr><td colspan="${this.columns.length}">
            <div class="empty-state">
              <i class="bi bi-inbox"></i>
              <h3>No results match these filters</h3>
              <p>Try widening your search or clearing filters.</p>
            </div>
          </td></tr>`;
        } else {
          tbody.innerHTML = pageRows.map(row => `<tr>${
            this.columns.map(col => `<td>${col.render ? col.render(row) : (row[col.key] ?? '')}</td>`).join('')
          }</tr>`).join('');
        }
      }
  
      if (this.paginationEl) this._renderPagination(filtered.length, totalPages);
      if (this.onRowsChange) this.onRowsChange(pageRows);
    }
  
    _renderPagination(total, totalPages) {
      const p = this.state.page;
      const start = total === 0 ? 0 : (p - 1) * this.pageSize + 1;
      const end = Math.min(total, p * this.pageSize);
  
      let btns = "";
      const maxBtns = 5;
      let from = Math.max(1, p - 2), to = Math.min(totalPages, from + maxBtns - 1);
      from = Math.max(1, to - maxBtns + 1);
      for (let i = from; i <= to; i++) {
        btns += `<button data-page="${i}" class="${i === p ? 'active' : ''}">${i}</button>`;
      }
  
      this.paginationEl.innerHTML = `
        <div class="text-muted text-sm">Showing <strong style="color:var(--text)">${start}–${end}</strong> of <strong style="color:var(--text)">${total}</strong></div>
        <div class="page-btns">
          <button data-page="prev" ${p === 1 ? 'disabled' : ''}><i class="bi bi-chevron-left"></i></button>
          ${btns}
          <button data-page="next" ${p === totalPages ? 'disabled' : ''}><i class="bi bi-chevron-right"></i></button>
        </div>`;
  
      this.paginationEl.querySelectorAll("button").forEach(btn => {
        btn.addEventListener("click", () => {
          const val = btn.dataset.page;
          if (val === "prev") this.state.page = Math.max(1, this.state.page - 1);
          else if (val === "next") this.state.page = Math.min(totalPages, this.state.page + 1);
          else this.state.page = parseInt(val, 10);
          this.render();
          this.table.closest(".xdr-table-wrap")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
        });
      });
    }
  }
  
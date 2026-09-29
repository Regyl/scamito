"""Local read-only web UI for hosts, services, and CVEs."""

from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from web import queries

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

app = FastAPI(title="Scan inventory", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


def _qs(**params: object) -> str:
    items = []
    for key, value in params.items():
        if value is None or value == "" or (key == "page" and value == 1):
            continue
        items.append((key, value))
    return urlencode(items)


def _severity_key(value: str | None) -> str:
    key = (value or "").strip().lower()
    if key in ("critical", "high", "medium", "low"):
        return key
    return "unknown"


def _format_score(value) -> str:
    if value is None:
        return "—"
    return f"{float(value):.1f}"


templates.env.filters["severity_key"] = _severity_key
templates.env.filters["severity_label"] = lambda value: _severity_key(value).capitalize()
templates.env.filters["score"] = _format_score
templates.env.filters["ip_path"] = lambda value: quote(str(value), safe="")
templates.env.globals["qs"] = _qs
templates.env.globals["severity_keys"] = queries.SEVERITY_KEYS


def _render(request: Request, name: str, *, active: str, status_code: int = 200, **context):
    context.setdefault("db_error", None)
    context["active"] = active
    return templates.TemplateResponse(
        request=request,
        name=name,
        context=context,
        status_code=status_code,
    )


def _load(fn, *args):
    try:
        return fn(*args), None
    except queries.DatabaseError as exc:
        return None, str(exc)


def _page_info(result: dict | None) -> dict | None:
    if result is None:
        return None
    total = result["total"]
    page = result["page"]
    page_size = result["page_size"]
    pages = max(1, (total + page_size - 1) // page_size) if total else 1
    start = 0 if total == 0 else (page - 1) * page_size + 1
    return {
        "page": page,
        "pages": pages,
        "start": start,
        "end": min(page * page_size, total),
        "total": total,
        "has_prev": page > 1,
        "has_next": page < pages,
    }


@app.exception_handler(404)
async def handle_not_found(request: Request, exc: HTTPException):
    if request.url.path.startswith("/static"):
        return await http_exception_handler(request, exc)
    detail = str(exc.detail or "")
    if detail in ("", "Not Found"):
        detail = "That page does not exist."
    return _render(
        request,
        "not_found.html",
        active="",
        status_code=404,
        message=detail,
    )


@app.get("/", response_class=HTMLResponse)
def overview(request: Request):
    data, error = _load(queries.overview)
    return _render(request, "index.html", active="overview", overview=data, db_error=error)


@app.get("/hosts", response_class=HTMLResponse)
def hosts(
    request: Request,
    q: str = Query(""),
    page: int = Query(1),
):
    data, error = _load(queries.list_hosts, q, page)
    return _render(
        request,
        "hosts.html",
        active="hosts",
        result=data,
        page_info=_page_info(data),
        q=q.strip(),
        list_path="/hosts",
        db_error=error,
    )


@app.get("/hosts/{ip}", response_class=HTMLResponse)
def host_detail(request: Request, ip: str):
    data, error = _load(queries.host_detail, ip)
    if error:
        return _render(request, "host.html", active="hosts", host=None, db_error=error)
    if data is None:
        raise HTTPException(status_code=404, detail="This host is not in the database.")
    return _render(request, "host.html", active="hosts", host=data)


@app.get("/cves", response_class=HTMLResponse)
def cves(
    request: Request,
    q: str = Query(""),
    severity: str = Query(""),
    page: int = Query(1),
):
    selected = severity.strip().lower()
    if selected not in queries.SEVERITY_KEYS:
        selected = ""
    data, error = _load(queries.list_cves, q, selected, page)
    return _render(
        request,
        "cves.html",
        active="cves",
        result=data,
        page_info=_page_info(data),
        q=q.strip(),
        severity=selected,
        list_path="/cves",
        db_error=error,
    )

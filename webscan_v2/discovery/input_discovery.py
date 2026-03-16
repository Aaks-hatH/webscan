"""discovery/input_discovery.py"""
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

from crawler.async_crawler import PageResult

_API_RE = re.compile(r"/(?:api|v\d+|graphql|rest|service)/?", re.I)
_ID_RE  = re.compile(r"/([\d]{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)", re.I)


@dataclass
class InputVector:
    url:           str
    method:        str
    param_name:    str
    param_type:    str   # query | form | json | path
    example_value: str   = ""
    form_data:     dict  = field(default_factory=dict)
    source_page:   str   = ""


@dataclass
class InputSurface:
    query_params:  list[InputVector] = field(default_factory=list)
    form_inputs:   list[InputVector] = field(default_factory=list)
    api_endpoints: list[InputVector] = field(default_factory=list)
    path_params:   list[InputVector] = field(default_factory=list)

    @property
    def all_vectors(self) -> list[InputVector]:
        return self.query_params + self.form_inputs + self.api_endpoints + self.path_params

    def summary(self) -> dict:
        return {
            "total": len(self.all_vectors),
            "query_params":  len(self.query_params),
            "form_inputs":   len(self.form_inputs),
            "api_endpoints": len(self.api_endpoints),
            "path_params":   len(self.path_params),
        }


class InputDiscovery:
    def __init__(self, pages: list[PageResult]):
        self.pages = pages

    def run(self) -> InputSurface:
        s = InputSurface()
        for page in self.pages:
            if page.error:
                continue
            for k, v in page.query_params.items():
                s.query_params.append(InputVector(
                    url=page.url, method="GET", param_name=k,
                    param_type="query", example_value=(v[0] if v else ""),
                    source_page=page.url,
                ))
            base = {i.name: i.value for form in page.forms for i in form.inputs}
            for form in page.forms:
                for inp in form.inputs:
                    if inp.input_type in ("submit", "button", "reset"):
                        continue
                    s.form_inputs.append(InputVector(
                        url=form.action, method=form.method,
                        param_name=inp.name, param_type="form",
                        example_value=inp.value, form_data=base,
                        source_page=page.url,
                    ))
            path = urlparse(page.url).path
            for m in _ID_RE.finditer(path):
                s.path_params.append(InputVector(
                    url=page.url, method="GET",
                    param_name="<path-id>", param_type="path",
                    example_value=m.group(1), source_page=page.url,
                ))
            if _API_RE.search(path) and "json" in page.content_type.lower():
                s.api_endpoints.append(InputVector(
                    url=page.url, method="GET",
                    param_name="<json-body>", param_type="json",
                    source_page=page.url,
                ))

        s.query_params  = _dedup(s.query_params)
        s.form_inputs   = _dedup(s.form_inputs)
        s.path_params   = _dedup(s.path_params)
        s.api_endpoints = _dedup(s.api_endpoints)
        return s


def _dedup(vs: list[InputVector]) -> list[InputVector]:
    seen: set[tuple] = set()
    out: list[InputVector] = []
    for v in vs:
        k = (v.url, v.method, v.param_name, v.param_type)
        if k not in seen:
            seen.add(k)
            out.append(v)
    return out

import shutil
import uuid
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime
import datetime as _dt
import xml.etree.ElementTree as ET
from typing import Optional

# Configuration
TMP_DIR = Path(__file__).resolve().parent.parent / "storage" / "tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)

_aspose_probe_done = False
_aspose_available = False
_aspose_error = None

def _probe_aspose():
    global _aspose_probe_done, _aspose_available, _aspose_error
    if _aspose_probe_done:
        return _aspose_available, _aspose_error
    try:
        code = "import aspose.tasks as at; print(getattr(at, '__version__', 'ok'))"
        res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        if res.returncode == 0:
            _aspose_available = True
            _aspose_error = None
        else:
            _aspose_available = False
            err = (res.stderr or res.stdout or "").strip()
            if not err:
                err = f"import_failed_code_{res.returncode}"
            _aspose_error = err
    except Exception as e:
        _aspose_available = False
        _aspose_error = str(e)
    _aspose_probe_done = True
    return _aspose_available, _aspose_error

def _ensure_aspose_available():
    ok, err = _probe_aspose()
    if not ok:
        raise RuntimeError(f"Aspose.Tasks недоступен: {err or 'unknown_error'}")

def _get_aspose_tasks():
    _ensure_aspose_available()
    import aspose.tasks as at
    return at

def _apply_aspose_license():
    try:
        at = _get_aspose_tasks()
        lic = at.License()
        candidate = Path(__file__).resolve().parent.parent / 'Aspose.Tasks.lic'
        if candidate.exists():
            lic.set_license(str(candidate))
    except Exception:
        pass

_apply_aspose_license()

def _aspose_open_project(path: Path):
    at = _get_aspose_tasks()
    src = path
    tmp_copy = None
    try:
        # Aspose on Linux/Windows might have issues with non-ascii paths if not handled carefully
        # Safe approach: copy to tmp if needed, or just open
        if any(ord(ch) > 127 for ch in str(src)):
            tmp_copy = TMP_DIR / f"{uuid.uuid4().hex}{src.suffix or ''}"
            shutil.copyfile(str(src), str(tmp_copy))
            return at.Project(str(tmp_copy)), tmp_copy
        return at.Project(str(src)), None
    except Exception:
        if tmp_copy and tmp_copy.exists():
            try:
                tmp_copy.unlink()
            except Exception:
                pass
        raise

def parse_project_meta_aspose(path: Path) -> Optional[dict]:
    try:
        prj, tmp_copy = _aspose_open_project(path)
    except Exception:
        return None
    name = None
    percent = None
    author = None
    try:
        name = getattr(prj, 'name', None)
    except Exception:
        name = None
    try:
        if not name:
            name = getattr(prj.root_task, 'name', None)
    except Exception:
        pass
    try:
        percent = getattr(prj.root_task, 'percent_complete', None)
    except Exception:
        percent = None
    try:
        author = getattr(prj, 'author', None)
    except Exception:
        author = None
    if not author:
        try:
            at = _get_aspose_tasks()
            author = prj.get(at.Prj.AUTHOR)
        except Exception:
            author = author
    resources_set = set()
    try:
        for r in getattr(prj, 'resources', []):
            rn = getattr(r, 'name', None)
            if rn:
                resources_set.add(rn)
    except Exception:
        pass
    if not resources_set:
        try:
            for a in getattr(prj, 'resource_assignments', []):
                try:
                    res = getattr(a, 'resource', None)
                    rn = getattr(res, 'name', None) if res else None
                    if rn:
                        resources_set.add(rn)
                except Exception:
                    continue
        except Exception:
            pass
    start_date = None
    finish_date = None
    try:
        start_date = getattr(prj, 'start_date', None)
        finish_date = getattr(prj, 'finish_date', None)
    except Exception:
        start_date = None
        finish_date = None

    min_start = None
    max_finish = None
    max_actual_finish = None
    res_from_tasks = set()
    pc_sum = 0.0
    pc_cnt = 0
    try:
        at = _get_aspose_tasks()
        stack = list(getattr(prj.root_task, 'children', []))
        while stack:
            t = stack.pop()
            try:
                for ch in getattr(t, 'children', []):
                    stack.append(ch)
            except Exception:
                pass
            sd = getattr(t, 'start', None)
            fd = getattr(t, 'finish', None)
            if sd is not None:
                if min_start is None or sd < min_start:
                    min_start = sd
            if fd is not None:
                if max_finish is None or fd > max_finish:
                    max_finish = fd
            af = None
            try:
                af = t.get(at.Tsk.ACTUAL_FINISH)
            except Exception:
                af = getattr(t, 'actual_finish', None)
            if af is not None:
                try:
                    if max_actual_finish is None or af > max_actual_finish:
                        max_actual_finish = af
                except Exception:
                    pass
            rn_str = getattr(t, 'resource_names', None)
            if rn_str:
                for n in str(rn_str).split(','):
                    nn = n.strip()
                    if nn:
                        res_from_tasks.add(nn)
            pc_val = getattr(t, 'percent_complete', None)
            if pc_val is not None:
                try:
                    pc_sum += float(pc_val)
                    pc_cnt += 1
                except Exception:
                    pass
    except Exception:
        pass
    if start_date is None and min_start is not None:
        start_date = min_start
    if finish_date is None and max_finish is not None:
        finish_date = max_finish
    if not resources_set and res_from_tasks:
        resources_set = res_from_tasks
    if percent is None and pc_cnt > 0:
        percent = pc_sum / pc_cnt
    meta = {
        'name': name,
        'author': author,
        'resources': ', '.join(sorted(resources_set)) if resources_set else None,
        'start_date': start_date,
        'finish_date': finish_date,
        'actual_finish_date': max_actual_finish,
        'percent_complete': percent,
    }
    if tmp_copy and tmp_copy.exists():
        try:
            tmp_copy.unlink()
        except Exception:
            pass
    return meta

def parse_project_meta_xml(path: Path) -> Optional[dict]:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        tag = root.tag
        ns = None
        if tag.startswith('{'):
            ns = tag[1:tag.index('}')]
        def q(t: str) -> str:
            return f"{{{ns}}}{t}" if ns else t

        pn_el = root.find(q('Name'))
        pa_el = root.find(q('Author'))
        ps_el = root.find(q('StartDate'))
        pf_el = root.find(q('FinishDate'))

        name = pn_el.text if pn_el is not None else None
        author = pa_el.text if pa_el is not None else None
        percent = None

        min_start = None
        max_finish = None
        percent_sum = 0.0
        percent_count = 0
        max_actual_finish = None
        res_from_tasks: set[str] = set()

        tasks_el = root.find(q('Tasks'))
        if tasks_el is not None:
            for t in tasks_el.findall(q('Task')):
                s = t.find(q('Summary'))
                ol = t.find(q('OutlineLevel'))
                if s is not None and s.text in ('1','True','true') and ol is not None and ol.text in ('1','0'):
                    n = t.find(q('Name'))
                    pc = t.find(q('PercentComplete'))
                    if n is not None and n.text:
                        name = n.text
                    if pc is not None and pc.text:
                        try:
                            percent = float(pc.text)
                        except Exception:
                            percent = None
                st = t.find(q('Start'))
                fn = t.find(q('Finish'))
                af = t.find(q('ActualFinish'))
                def parse_dt_xml(s):
                    from datetime import datetime
                    if not s:
                        return None
                    try:
                        s2 = s.replace('Z','+00:00')
                        return datetime.fromisoformat(s2)
                    except Exception:
                        return None
                if st is not None and st.text:
                    sd = parse_dt_xml(st.text)
                    if sd is not None and (min_start is None or sd < min_start):
                        min_start = sd
                if fn is not None and fn.text:
                    fd = parse_dt_xml(fn.text)
                    if fd is not None and (max_finish is None or fd > max_finish):
                        max_finish = fd
                if af is not None and af.text:
                    ad = parse_dt_xml(af.text)
                    if ad is not None and (max_actual_finish is None or ad > max_actual_finish):
                        max_actual_finish = ad
                rn = t.find(q('ResourceNames'))
                if rn is not None and rn.text:
                    for part in rn.text.split(','):
                        nm = part.strip()
                        if nm:
                            res_from_tasks.add(nm)
                pc = t.find(q('PercentComplete'))
                if pc is not None and pc.text:
                    try:
                        percent_sum += float(pc.text)
                        percent_count += 1
                    except Exception:
                        pass

        resources = None
        resources_el = root.find(q('Resources'))
        if resources_el is not None:
            names = []
            for r in resources_el.findall(q('Resource')):
                n = r.find(q('Name'))
                if n is not None and n.text:
                    names.append(n.text)
            if names:
                resources = ', '.join(sorted(set(names)))
        if not resources and res_from_tasks:
            resources = ', '.join(sorted(res_from_tasks))

        def parse_dt(s):
            if not s:
                return None
            try:
                s2 = s.replace('Z','+00:00')
                return datetime.fromisoformat(s2)
            except Exception:
                return None

        start_dt = parse_dt(ps_el.text if ps_el is not None else None)
        finish_dt = parse_dt(pf_el.text if pf_el is not None else None)
        if start_dt is None and min_start is not None:
            start_dt = min_start
        if finish_dt is None and max_finish is not None:
            finish_dt = max_finish
        if percent is None and percent_count > 0:
            percent = percent_sum / percent_count
        return {
            'name': name,
            'author': author,
            'resources': resources,
            'start_date': start_dt,
            'finish_date': finish_dt,
            'actual_finish_date': max_actual_finish,
            'percent_complete': percent,
        }
    except Exception:
        return None

def parse_project_meta(path: Path) -> Optional[dict]:
    if path.suffix.lower() == '.xml':
        return parse_project_meta_xml(path)
    try:
        meta = parse_project_meta_aspose(path)
        if meta:
            # Fallback to XML conversion if some data is missing in Aspose parsing
            needs_xml = (
                meta.get('resources') is None or
                meta.get('start_date') is None or
                meta.get('finish_date') is None or
                meta.get('percent_complete') is None or
                meta.get('author') is None
            )
            if not needs_xml:
                return meta
            try:
                at = _get_aspose_tasks()
                prj, tmp_copy = _aspose_open_project(path)
                tmp_xml = TMP_DIR / f"{uuid.uuid4().hex}.xml"
                try:
                    prj.save(str(tmp_xml), at.SaveFileFormat.XML)
                    xml_meta = parse_project_meta_xml(tmp_xml)
                finally:
                    try:
                        if tmp_xml.exists():
                            tmp_xml.unlink()
                        if 'tmp_copy' in locals() and tmp_copy and tmp_copy.exists():
                            tmp_copy.unlink()
                    except Exception:
                        pass
                if xml_meta:
                    return {
                        'name': meta.get('name') or xml_meta.get('name'),
                        'author': meta.get('author') or xml_meta.get('author'),
                        'resources': meta.get('resources') or xml_meta.get('resources'),
                        'start_date': meta.get('start_date') or xml_meta.get('start_date'),
                        'finish_date': meta.get('finish_date') or xml_meta.get('finish_date'),
                        'percent_complete': meta.get('percent_complete') or xml_meta.get('percent_complete'),
                        'actual_finish_date': meta.get('actual_finish_date') or xml_meta.get('actual_finish_date'),
                    }
                return meta
            except Exception:
                return meta
    except Exception:
        pass
    return None

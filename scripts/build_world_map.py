"""Convert a manually acquired Natural Earth 110m GeoJSON to bundled SVG paths.

Usage: python scripts/build_world_map.py /path/to/ne_110m_admin_0_countries.geojson
This build helper performs no network access; never used at startup or Docker build.
"""

import json
import sys
from pathlib import Path


def convert(source):
    countries = {}
    for feature in source["features"]:
        properties = feature["properties"]
        code = properties["ISO_A2_EH"]
        if properties["ADMIN"] == "Antarctica":
            continue
        if code == "-99":
            code = {"Somaliland": "SO", "Northern Cyprus": "CY"}[properties["ADMIN"]]
        geometry = feature["geometry"]
        polygons = (
            geometry["coordinates"]
            if geometry["type"] == "MultiPolygon"
            else [geometry["coordinates"]]
        )
        rings = []
        for polygon in polygons:
            for ring in polygon:
                points = [
                    (round((lon + 180) * 3, 1), round((85 - lat) * 3, 1)) for lon, lat in ring
                ]
                rings.append("M" + "L".join(f"{x:g},{y:g}" for x, y in points) + "Z")
        country = countries.setdefault(code, dict(code=code, name=properties["NAME_EN"], path=""))
        country["path"] += "".join(rings)
        if properties["ISO_A2_EH"] != "-99":
            country["name"] = properties["NAME_EN"]
    return list(countries.values())


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "app/static/world-countries.json"
    target.write_text(
        json.dumps(convert(json.loads(Path(sys.argv[1]).read_text())), separators=(",", ":")) + "\n"
    )

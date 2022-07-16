# rzodkiewka

Downloads CWE and CVE files, then simplify data and saves them as json files.
cwe.json file has all the data, CVEs are splitted in files named after CWE.
Library for sarenka app.

1. Downloads CWE xml file from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
2. Saves CWEs in .\output\cwe.json
3. Downloads CVE files from https://nvd.nist.gov/vuln/data-feeds#JSON_FEED (in table with id "divJSONFeeds")
4. Saves CVEs in .\output\cve.json
5. Split CVEs by CWE and saves in files .\cve_output\CWE-<code>.json

```
pip install rzodkiewka
```

### example usage

```
from rzodkiewka.rzodkiewka import save_info

if __name__ == "__main__":
    save_info()
```

### fragment .\output\cwe.json

```
[
    {
        "id": 1,
        "code": "CWE-1004",
        "name": "Sensitive Cookie Without 'HttpOnly' Flag",
        "abstraction": "Variant",
        "structure": "Simple",
        "status": "Incomplete",
        "description": "The software uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.",
        "extended_description": "The HttpOnly flag directs compatible browsers to prevent client-side script from accessing cookies. Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate the risk associated with Cross-Site Scripting (XSS) where an attacker's script code might attempt to read the contents of a cookie and exfiltrate information obtained. When set, browsers that support the flag will not reveal the contents of the cookie to a third party via client-side script executed via XSS."
    },
...
```

### fragment .\output\cve.json

```
...
    {
        "id": 161,
        "cwe_code": "CWE-476",
        "description": "A CWE-476: NULL Pointer Dereference vulnerability exists that could cause a denial of service of the webserver when parsing JSON content type. Affected Products: X80 advanced RTU Communication Module (BMENOR2200H) (V2.01 and later), OPC UA Modicon Communication Module (BMENUA0100) (V1.10 and prior)",
        "code": "CVE-2022-34761",
        "published": "2022-07-13T21:15Z",
        "modified": "2022-07-14T12:41Z",
        "version": "4.0",
        "assigner": "cybersecurity@schneider-electric.com",
        "data_format": "MITRE",
        "references_list": [
            {
                "name": "N/A",
                "url": "https://download.schneider-electric.com/files?p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2022-193-01_OPC_UA_X80_Advanced_RTU_Modicon_Communication_Modules+_Security_Notification.pdf",
                "refsource": "CONFIRM",
                "tags": []
            }
        ],
        "cpe_list": [],
        "base_metric_v2": {},
        "base_metric_v3": {}
    },
...
```

### fragment .\cve_output\CWE-1.json

```
[
    {
        "id": 1496,
        "cwe_code": "CWE-1",
        "description": "In all Qualcomm products with Android releases from CAF using the Linux kernel, the UE can send unprotected MeasurementReports revealing UE location.",
        "code": "CVE-2016-10380",
        "published": "2017-08-18T18:29Z",
        "modified": "2018-04-19T01:29Z",
        "version": "4.0",
        "assigner": "security.cna@qualcomm.com",
        "data_format": "MITRE",
        "references_list": [
            {
                "name": "https://source.android.com/security/bulletin/2017-07-01",
                "url": "https://source.android.com/security/bulletin/2017-07-01",
                "refsource": "CONFIRM",
                "tags": [
                    "vendor_advisory"
                ]
            },
            {
                "name": "103671",
                "url": "http://www.securityfocus.com/bid/103671",
                "refsource": "BID",
                "tags": []
            },
            {
                "name": "https://source.android.com/security/bulletin/2018-04-01",
                "url": "https://source.android.com/security/bulletin/2018-04-01",
                "refsource": "CONFIRM",
                "tags": []
            }
        ],
        "cpe_list": [
            {
                "uri": "cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
                "is_vulnerable": true
            }
        ],
        "base_metric_v2": {
            "cvss_v2": {
                "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "version": "2.0",
                "access_vector": "NETWORK",
                "access_complexity": "LOW",
                "authentication": "NONE",
                "confidentiality_impact": "COMPLETE",
                "integrity_impact": "COMPLETE",
                "availability_impact": "COMPLETE",
                "base_score": 10.0
            },
            "severity": "HIGH",
            "exploitability_score": 10.0,
            "impact_score": 10.0,
            "is_obtain_all_privilege": false,
            "is_obtain_user_privilege": false,
            "is_obtain_other_privilege": false,
            "is_user_interaction_required": false
        },
        "base_metric_v3": {
            "cvss_v3": {
                "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "version": "3.0",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "base_score": 9.8,
                "base_severity": "CRITICAL"
            },
            "exploitability_score": 3.9,
            "impact_score": 5.9
        }
    },
...
```

#### create python package

- https://www.youtube.com/watch?v=tEFkHEKypLI

```
pip install setuptools
pip install wheel # error: invalid command 'bdist_wheel'
python setup.py sdist bdist_wheel
pip install twine
twine upload dist/*
```

### TODO

- test
- typing
- docstring

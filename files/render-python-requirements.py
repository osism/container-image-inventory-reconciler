# SPDX-License-Identifier: Apache-2.0

import jinja2
import yaml

# load versions files from release repository

with open("/release/latest/base.yml", "rb") as fp:
    versions = yaml.load(fp, Loader=yaml.FullLoader)

# prepare jinja2 environment

loader = jinja2.FileSystemLoader(searchpath="/templates/")
environment = jinja2.Environment(loader=loader)

# render requirements.txt

template = environment.get_template("requirements.txt.j2")
result = template.render({"osism_projects": versions["osism_projects"]})
with open("/requirements.extra.txt", "w+") as fp:
    fp.write(result)

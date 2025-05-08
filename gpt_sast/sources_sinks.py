"""
Sources, sinks, and sanitizers for different programming languages.
Used for dataflow analysis to identify potential security vulnerabilities.
"""

def get_sources(language):
    """Get input sources for a specific language."""
    if language == "java":
        return get_java_sources()
    elif language == "javascript" or language == "typescript":
        return get_js_sources()
    elif language == "python":
        return get_python_sources()
    else:
        return get_generic_sources()

def get_sinks(language):
    """Get vulnerability sinks for a specific language."""
    if language == "java":
        return get_java_sinks()
    elif language == "javascript" or language == "typescript":
        return get_js_sinks()
    elif language == "python":
        return get_python_sinks()
    else:
        return get_generic_sinks()

def get_sanitizers(language):
    """Get sanitization functions for a specific language."""
    if language == "java":
        return get_java_sanitizers()
    elif language == "javascript" or language == "typescript":
        return get_js_sanitizers()
    elif language == "python":
        return get_python_sanitizers()
    else:
        return get_generic_sanitizers()

# Java sources, sinks, and sanitizers
def get_java_sources():
    """Get Java-specific input sources."""
    return {
        "http_request": [
            "request.getParameter",
            "request.getHeader",
            "request.getQueryString",
            "request.getRequestURI",
            "request.getRequestURL",
            "request.getCookies",
            "HttpServletRequest",
            "getInputStream",
            "getReader",
            "@RequestParam",
            "@PathVariable",
            "@RequestBody"
        ],
        "file_input": [
            "new FileInputStream",
            "new FileReader",
            "new Scanner",
            "new BufferedReader",
            "Files.readAllBytes",
            "Files.readAllLines",
            "Files.lines",
            "readLine"
        ],
        "database_input": [
            "executeQuery",
            "executeQueryAndGetResults",
            "getResultSet",
            "next()",
            "getString",
            "getInt",
            "getObject"
        ],
        "system_input": [
            "System.getProperty",
            "System.getenv",
            "getProperties",
            "getEnvironment"
        ],
        "user_input": [
            "new Scanner(System.in)",
            "readLine()",
            "console.readLine",
            "console.readPassword"
        ]
    }

def get_java_sinks():
    """Get Java-specific vulnerability sinks."""
    return {
        "sql_injection": [
            "executeQuery(",
            "executeUpdate(",
            "execute(",
            "prepareStatement(",
            "createStatement(",
            "createNativeQuery("
        ],
        "command_injection": [
            "Runtime.exec(",
            "Runtime.getRuntime().exec(",
            "ProcessBuilder(",
            ".start()",
            "Process"
        ],
        "xss": [
            "response.getWriter().print",
            "response.getWriter().write",
            "response.getWriter().append",
            "out.print",
            "out.write",
            "out.append",
            "response.setHeader",
            "response.addHeader",
            "response.sendRedirect"
        ],
        "path_traversal": [
            "new File(",
            "new FileInputStream(",
            "new FileOutputStream(",
            "new FileReader(",
            "new FileWriter(",
            "Files.write",
            "Files.createFile",
            "Paths.get"
        ],
        "xxe": [
            "DocumentBuilderFactory",
            "DocumentBuilder",
            "SAXParserFactory",
            "SAXParser",
            "XMLReader",
            "TransformerFactory",
            "SchemaFactory"
        ],
        "deserialization": [
            "readObject(",
            "readUnshared(",
            "readExternal(",
            "readResolve(",
            "ObjectInputStream",
            "XMLDecoder"
        ],
        "ldap_injection": [
            "search(",
            "searchControls(",
            "DirContext",
            "InitialDirContext",
            "NamingEnumeration"
        ],
        "open_redirect": [
            "sendRedirect("
        ]
    }

def get_java_sanitizers():
    """Get Java-specific sanitization functions."""
    return {
        "sql_sanitization": [
            "PreparedStatement",
            "setString",
            "setInt",
            "setLong",
            "setDate",
            "setObject",
            "createParameterizedQuery"
        ],
        "command_sanitization": [
            "ProcessBuilder.command",  # When used properly with lists
            "Runtime.exec(String[])"   # When used properly with arrays
        ],
        "xss_sanitization": [
            "escapeHtml",
            "htmlEscape",
            "htmlEncode",
            "encodeForHTML",
            "escapeXml",
            "StringEscapeUtils"
        ],
        "path_sanitization": [
            "getCanonicalPath",
            "normalize",
            "validateFilePath",
            "FilenameUtils.normalize"
        ],
        "xml_sanitization": [
            "setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\"",
            "setFeature(\"http://xml.org/sax/features/external-general-entities\", false",
            "setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false",
            "setExpandEntityReferences(false"
        ]
    }

# JavaScript/TypeScript sources, sinks, and sanitizers
def get_js_sources():
    """Get JavaScript-specific input sources."""
    return {
        "dom_input": [
            "document.URL",
            "document.documentURI",
            "document.URLUnencoded",
            "document.baseURI",
            "location",
            "document.cookie",
            "document.referrer",
            "window.name",
            "history.pushState",
            "history.replaceState",
            "localStorage",
            "sessionStorage",
            "$.ajax",
            "$.get",
            "$.post",
            "XMLHttpRequest",
            "fetch("
        ],
        "user_input": [
            "getElementById",
            "getElementsByClassName",
            "getElementsByName",
            "getElementsByTagName",
            "querySelector",
            "querySelectorAll",
            ".value",
            ".innerHTML",
            ".outerHTML",
            ".textContent",
            "formData",
            "new FormData",
            "prompt(",
            ".elements"
        ],
        "url_input": [
            "location.hash",
            "location.search",
            "location.href",
            "location.pathname",
            "URLSearchParams",
            "URL",
            "document.baseURI"
        ],
        "node_input": [
            "req.body",
            "req.query",
            "req.params",
            "req.cookies",
            "req.headers",
            "req.url",
            "req.file",
            "req.files",
            "process.env",
            "fs.readFile",
            "fs.readFileSync"
        ]
    }

def get_js_sinks():
    """Get JavaScript-specific vulnerability sinks."""
    return {
        "xss": [
            ".innerHTML =",
            ".outerHTML =",
            ".insertAdjacentHTML",
            "document.write(",
            "document.writeln(",
            ".html(",
            "dangerouslySetInnerHTML",
            "angular.element",
            "jQuery(",
            "$(",
            ".append(",
            ".prepend(",
            ".before(",
            ".after("
        ],
        "dom_xss": [
            "eval(",
            "Function(",
            "setTimeout(",
            "setInterval(",
            "setImmediate(",
            "execScript(",
            "new Function(",
            "document.evaluate"
        ],
        "open_redirect": [
            "location =",
            "location.href =",
            "location.replace(",
            "location.assign(",
            "window.open(",
            "window.location =",
            "window.location.href ="
        ],
        "sql_injection": [
            "executeQuery(",
            "db.query(",
            "connection.query(",
            "pool.query(",
            "knex.raw(",
            "sequelize.query("
        ],
        "nosql_injection": [
            "find(",
            "findOne(",
            "findById(",
            "update(",
            "updateOne(",
            "deleteOne(",
            "remove(",
            "MongoClient",
            "mongodb",
            "mongoose"
        ],
        "command_injection": [
            "exec(",
            "execSync(",
            "spawn(",
            "spawnSync(",
            "execFile(",
            "child_process",
            "shelljs",
            "require('child_process')"
        ],
        "path_traversal": [
            "fs.readFile(",
            "fs.readFileSync(",
            "fs.writeFile(",
            "fs.writeFileSync(",
            "fs.appendFile(",
            "createReadStream(",
            "createWriteStream("
        ],
        "prototype_pollution": [
            "Object.assign(",
            "Object.merge(",
            "_.merge(",
            "_.extend(",
            "$.extend(",
            "deepMerge("
        ]
    }

def get_js_sanitizers():
    """Get JavaScript-specific sanitization functions."""
    return {
        "xss_sanitization": [
            "textContent =",
            "DOMPurify.sanitize(",
            "escapeHTML(",
            "sanitizeHTML(",
            "encodeURIComponent(",
            "String.prototype.entityify",
            "React.createElement(",
            "sanitize-html",
            "escape("
        ],
        "sql_sanitization": [
            "parameterized",
            "prepared",
            "placeholder",
            "escape(",
            "mysql.escape(",
            "pg.parameterize",
            "knex.raw",
            "sequelize.escape"
        ],
        "command_sanitization": [
            "execFile", # When used properly instead of exec
            "spawn",    # When used properly with array args
            "child_process.execFile"
        ],
        "path_sanitization": [
            "path.normalize(",
            "path.resolve(",
            "normalizeFilePath(",
            "validatePath("
        ],
        "general_validation": [
            "validator.",
            "validate(",
            "sanitize(",
            "check(",
            "assert(",
            "is-valid",
            "isValid"
        ]
    }

# Python sources, sinks, and sanitizers
def get_python_sources():
    """Get Python-specific input sources."""
    return {
        "http_request": [
            "request.GET",
            "request.POST",
            "request.FILES",
            "request.COOKIES",
            "request.META",
            "request.headers",
            "request.body",
            "request.args",
            "request.form",
            "request.values",
            "request.json",
            "request.data",
            "flask.request",
            "django.request",
            "fastapi.Request",
            "cherrypy.request",
            "bottle.request"
        ],
        "user_input": [
            "input(",
            "raw_input(",
            "sys.stdin",
            "fileinput",
            "getpass.getpass"
        ],
        "file_input": [
            "open(",
            "file(",
            "os.open",
            "io.open",
            "read(",
            "readlines(",
            "with open"
        ],
        "environment": [
            "os.environ",
            "os.getenv(",
            "subprocess.environ",
            "socket.gethostname"
        ],
        "database_input": [
            "cursor.execute",
            "connection.execute",
            "session.execute",
            "query.filter",
            "objects.filter",
            "objects.get",
            "raw(",
            "execute_sql",
            "get_object_or_404"
        ]
    }

def get_python_sinks():
    """Get Python-specific vulnerability sinks."""
    return {
        "sql_injection": [
            "cursor.execute(",
            "connection.execute(",
            "session.execute(",
            "raw(",
            "raw_query",
            "execute_sql(",
            "executemany(",
            "executescript("
        ],
        "command_injection": [
            "os.system(",
            "os.popen(",
            "os.spawn",
            "os.exec",
            "subprocess.call(",
            "subprocess.Popen(",
            "subprocess.run(",
            "subprocess.check_output(",
            "subprocess.check_call(",
            "popen(",
            "commands.getoutput(",
            "commands.getstatusoutput(",
            "eval(",
            "exec(",
            "execfile(",
            "shell=True"
        ],
        "xss": [
            "render(",
            "render_template(",
            "render_to_response(",
            "HttpResponse(",
            "jsonify(",
            "Response(",
            "make_response(",
            "send_file(",
            "send_from_directory(",
            "template.render(",
            "mark_safe(",
            "format_html("
        ],
        "path_traversal": [
            "open(",
            "file(",
            "os.path",
            "os.makedirs",
            "os.mkdir",
            "os.rename",
            "os.replace",
            "os.link",
            "os.symlink",
            "os.unlink",
            "os.remove",
            "shutil.copy",
            "shutil.copytree",
            "shutil.move",
            "io.open"
        ],
        "xxe": [
            "xml.etree.ElementTree.parse(",
            "xml.dom.minidom.parse(",
            "xml.sax.parse(",
            "xml.parser.expat",
            "lxml.etree",
            "xmltodict.parse",
            "defusedxml",
            "xml.parsers.expat.ParserCreate"
        ],
        "deserialization": [
            "pickle.load(",
            "pickle.loads(",
            "cPickle.load(",
            "cPickle.loads(",
            "marshal.load(",
            "marshal.loads(",
            "yaml.load(",
            "yaml.load_all(",
            "json.load(",
            "json.loads("
        ],
        "template_injection": [
            "Template(",
            "render_template_string(",
            "from_string(",
            "template.render(",
            "jinja2.Template"
        ]
    }

def get_python_sanitizers():
    """Get Python-specific sanitization functions."""
    return {
        "sql_sanitization": [
            "paramstyle",
            "placeholder",
            "cursor.mogrify(",
            "sqlalchemy.text(",
            "db.escape_string(",
            "MySQLdb.escape_string(",
            "psycopg2.extensions.quote_ident(",
            "psycopg2.extensions.adapt("
        ],
        "command_sanitization": [
            "pipes.quote(",
            "shlex.quote(",
            "shell=False",
            "args"  # When subprocess is used with args list
        ],
        "xss_sanitization": [
            "escape(",
            "html.escape(",
            "cgi.escape(",
            "bleach.clean(",
            "bleach.sanitize(",
            "django.utils.html.escape(",
            "django.utils.safestring.SafeString",
            "markupsafe.escape(",
            "jinja2.escape("
        ],
        "path_sanitization": [
            "os.path.normpath(",
            "os.path.abspath(",
            "os.path.realpath(",
            "pathlib.Path.resolve(",
            "pathvalidate."
        ],
        "deserialization_sanitization": [
            "yaml.safe_load(",
            "defusedxml",
            "defusedpickle",
            "restrict_types",
            "serializer.resolver"
        ]
    }

# Generic fallback sources, sinks, and sanitizers
def get_generic_sources():
    """Get language-agnostic input sources."""
    # Combine common patterns from all languages
    sources = {}
    for lang_sources in [get_java_sources(), get_js_sources(), get_python_sources()]:
        for source_type, patterns in lang_sources.items():
            if source_type not in sources:
                sources[source_type] = []
            sources[source_type].extend(patterns)
    
    # Remove duplicates
    for source_type in sources:
        sources[source_type] = list(set(sources[source_type]))
    
    return sources

def get_generic_sinks():
    """Get language-agnostic vulnerability sinks."""
    # Combine common patterns from all languages
    sinks = {}
    for lang_sinks in [get_java_sinks(), get_js_sinks(), get_python_sinks()]:
        for sink_type, patterns in lang_sinks.items():
            if sink_type not in sinks:
                sinks[sink_type] = []
            sinks[sink_type].extend(patterns)
    
    # Remove duplicates
    for sink_type in sinks:
        sinks[sink_type] = list(set(sinks[sink_type]))
    
    return sinks

def get_generic_sanitizers():
    """Get language-agnostic sanitization functions."""
    # Combine common patterns from all languages
    sanitizers = {}
    for lang_sanitizers in [get_java_sanitizers(), get_js_sanitizers(), get_python_sanitizers()]:
        for sanitizer_type, patterns in lang_sanitizers.items():
            if sanitizer_type not in sanitizers:
                sanitizers[sanitizer_type] = []
            sanitizers[sanitizer_type].extend(patterns)
    
    # Remove duplicates
    for sanitizer_type in sanitizers:
        sanitizers[sanitizer_type] = list(set(sanitizers[sanitizer_type]))
    
    return sanitizers
import ast
import json
import sys


def dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def is_dynamic_string(node):
    return isinstance(node, (ast.BinOp, ast.JoinedStr)) or (
        isinstance(node, ast.Call) and dotted_name(node.func).endswith(".format")
    )


def has_keyword(call, name, value=True):
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value == value:
            return True
    return False


def get_line(lines, node):
    line_no = getattr(node, "lineno", None)
    if not line_no or line_no > len(lines):
        return None
    return lines[line_no - 1].strip()


def finding(lines, node, title, category, severity, description, recommendation):
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "lineStart": getattr(node, "lineno", None),
        "lineEnd": getattr(node, "end_lineno", None) or getattr(node, "lineno", None),
        "description": description,
        "recommendation": recommendation,
        "evidence": get_line(lines, node),
        "confidence": 0.82,
    }


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.findings = []

    def visit_Call(self, node):
        name = dotted_name(node.func)
        first_arg = node.args[0] if node.args else None

        if name in {"eval", "exec"}:
            self.findings.append(
                finding(
                    self.lines,
                    node,
                    "Python AST: dynamic code execution",
                    "Unsafe APIs",
                    "high",
                    "Python AST found eval/exec. This can execute attacker-controlled code if untrusted data reaches it.",
                    "Remove dynamic execution and replace it with explicit parsing or allowlisted behavior.",
                )
            )

        if name in {"os.system", "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output"}:
            if has_keyword(node, "shell", True) or is_dynamic_string(first_arg):
                self.findings.append(
                    finding(
                        self.lines,
                        node,
                        "Python AST: command injection sink",
                        "Command injection",
                        "high",
                        "Python AST found shell command execution with shell=True or a dynamically built command.",
                        "Avoid shell=True and pass allowlisted argument arrays to subprocess APIs.",
                    )
                )

        if name.endswith(".execute") and is_dynamic_string(first_arg):
            self.findings.append(
                finding(
                    self.lines,
                    node,
                    "Python AST: dynamic SQL query",
                    "SQL Injection",
                    "high",
                    "Python AST found a database execute call using a dynamically constructed SQL string.",
                    "Use parameterized queries supported by the database driver.",
                )
            )

        if name == "yaml.load":
            has_safe_loader = any(
                keyword.arg == "Loader" and "SafeLoader" in dotted_name(keyword.value)
                for keyword in node.keywords
            )
            if not has_safe_loader:
                self.findings.append(
                    finding(
                        self.lines,
                        node,
                        "Python AST: unsafe YAML load",
                        "Unsafe APIs",
                        "medium",
                        "Python AST found yaml.load without SafeLoader, which can deserialize unsafe objects.",
                        "Use yaml.safe_load or yaml.load with SafeLoader.",
                    )
                )

        if name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
            self.findings.append(
                finding(
                    self.lines,
                    node,
                    "Python AST: unsafe deserialization",
                    "Unsafe APIs",
                    "high",
                    "Python AST found pickle/dill deserialization. Loading attacker-controlled data can execute code.",
                    "Avoid unsafe deserialization for untrusted data. Use JSON or a safe schema-based format.",
                )
            )

        if name.endswith("render_template_string"):
            self.findings.append(
                finding(
                    self.lines,
                    node,
                    "Python AST: template string rendering",
                    "XSS",
                    "medium",
                    "Python AST found render_template_string, which can introduce template injection or XSS when using untrusted input.",
                    "Render static templates and pass untrusted values as escaped template variables.",
                )
            )

        if name in {"ssl._create_unverified_context"} or has_keyword(node, "verify", False):
            self.findings.append(
                finding(
                    self.lines,
                    node,
                    "Python AST: TLS verification disabled",
                    "Unsafe APIs",
                    "critical",
                    "Python AST found TLS certificate verification disabled.",
                    "Keep TLS verification enabled and fix certificate trust issues directly.",
                )
            )

        if name.endswith("jwt.encode") and first_arg and isinstance(first_arg, ast.Dict):
            keys = {
                key.value
                for key in first_arg.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
            if "exp" not in keys:
                self.findings.append(
                    finding(
                        self.lines,
                        node,
                        "Python AST: JWT missing expiry",
                        "Authentication issues",
                        "medium",
                        "Python AST found JWT creation without an exp claim in the visible payload.",
                        "Add short expiration, issuer, audience, and use strong signing keys.",
                    )
                )

        self.generic_visit(node)


def main():
    content = sys.stdin.read()
    lines = content.splitlines()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        print(json.dumps({"findings": []}))
        return

    visitor = SecurityVisitor(lines)
    visitor.visit(tree)
    print(json.dumps({"findings": visitor.findings}))


if __name__ == "__main__":
    main()

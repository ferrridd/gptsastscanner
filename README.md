# GPT-SAST: Advanced GPT-Powered Static Application Security Testing

A powerful GPT-powered Static Application Security Testing (SAST) tool that uses advanced data flow analysis and AI to detect security vulnerabilities in source code with high accuracy and low false positives.

## Features

- **Data Flow Analysis**: Tracks how user input flows through applications to detect vulnerabilities
- **Taint Analysis**: Identifies how untrusted data can reach sensitive operations
- **AI-Driven Assessment**: Uses GPT to provide context-aware security analysis
- **False Positive Reduction**: Confidence scoring helps prioritize real issues
- **Language Support**: Works with multiple programming languages (Java, JavaScript, Python, etc.)
- **Smart File Selection**: Automatically identifies security-critical files
- **Interactive Reports**: Generates detailed HTML reports with filtering and visualization
- **Performance Optimization**: Caching and multi-threading for faster scanning

## Installation

```bash
# Clone the repository
git clone https://github.com/ferrridd/gpt-sast.git
cd gpt-sast

# Install dependencies
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python main.py /path/to/your/project --api-key your_openai_api_key
```

Advanced options:

```bash
python main.py /path/to/your/project \
  --api-key your_openai_api_key \
  --model gpt-4 \
  --output results.json \
  --html-report report.html \
  --max-file-size 100000 \
  --concurrent-scans 5 \
  --scan-all \
  --confidence-threshold 0.7 \
  --verbose
```

### Command Line Arguments

- `--api-key`: Your OpenAI API key (can also be set via OPENAI_API_KEY environment variable)
- `--model`: GPT model to use (default: gpt-4)
- `--output`: Path to save JSON results
- `--html-report`: Generate and save an HTML report
- `--verbose`: Enable verbose logging
- `--max-file-size`: Maximum file size in bytes to scan (default: 100000)
- `--max-files`: Maximum number of files to scan
- `--scan-all`: Scan all source files instead of just critical ones
- `--concurrent-scans`: Number of concurrent scans (default: 3)
- `--no-cache`: Disable caching of scan results
- `--confidence-threshold`: Confidence threshold for vulnerabilities (0.0-1.0)

## How It Works

1. **Project Structure Analysis**: Analyzes your project structure to understand how everything fits together
2. **Critical File Identification**: Uses AI and heuristics to identify security-critical files
3. **AST and Dataflow Analysis**: Parses code into abstract syntax trees and performs dataflow tracking
4. **Source-Sink Analysis**: Identifies how untrusted inputs can reach sensitive operations
5. **AI-Powered Assessment**: Uses GPT to analyze potential vulnerabilities in context
6. **Detailed Recommendations**: Provides specific remediation advice for identified issues

## Supported Languages

- Python
- JavaScript/TypeScript
- Java
- C/C++
- C#
- Go
- Ruby
- PHP
- Swift
- Kotlin
- Rust
- Scala
- Shell/Bash
- SQL
- HTML/CSS/XML

## Example

Scan a Java application for vulnerabilities:

```bash
python main.py /path/to/java/app --api-key your_openai_api_key --html-report report.html
```

### Example Report

The HTML report includes:
- Dashboard with risk score and vulnerability statistics
- Interactive charts showing vulnerability types and affected files
- Detailed listing of vulnerabilities with code snippets
- Comprehensive security recommendations
- Filtering options by severity, confidence, and file

## Key Advantages

- **Contextual Understanding**: Analyzes code in the context of your entire application
- **Data Flow Tracking**: Finds complex vulnerabilities that simple pattern matching would miss
- **False Positive Reduction**: Uses confidence scoring to prioritize real issues
- **Developer-Friendly Output**: Provides clear explanations and actionable remediation advice
- **Framework-Aware**: Understands common frameworks and their security patterns

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT

## Acknowledgements

- This project uses OpenAI's GPT models for code analysis
- Special thanks to the open-source security community for vulnerability patterns and best practices
```
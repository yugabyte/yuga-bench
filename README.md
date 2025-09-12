# YugabyteDB CIS Benchmark [YUGA-BENCH]

<div align="center">
  <img src="https://raw.githubusercontent.com/yugabyte/yugabyte-db/master/docs/static/images/ybsymbol_original.png" alt="YugabyteDB Logo" width="200"/>

  **Enterprise Security Compliance & Audit**

  [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
  [![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
  [![YugabyteDB](https://img.shields.io/badge/YugabyteDB-2.14%2B-orange)](https://yugabyte.com)
</div>

## 🔒 Overview

The **yuga-bench** is an enterprise-grade security auditing solution that provides comprehensive compliance assessment for YugabyteDB clusters based on Center for Internet Security (CIS) benchmarks. This tool enables organizations to maintain robust security postures and meet compliance requirements across their distributed SQL infrastructure.

### ✨ Key Features

- **🎯 Comprehensive Coverage**: Complete implementation of CIS benchmarks for YugabyteDB
- **📊 Multiple Report Formats**: Professional HTML, JSON, CSV, and console outputs

## 📋 Security Control Categories

Our tool systematically evaluates your YugabyteDB deployment across eight critical security domains:

| **Category** | **Controls** | **Focus Area** |
|--------------|--------------|----------------|
| 🔧 Installation and Patches | 15+ | Software integrity & updates |
| 📁 Directory and File Permissions | 20+ | File system security |
| 📝 Logging Monitoring and Auditing | 25+ | Audit trails & monitoring |
| 👥 User Access and Authorization | 18+ | Identity management |
| 🔐 Access Control and Password Policies | 22+ | Authentication security |
| 🌐 Connection and Login | 12+ | Network security |
| ⚙️ YugabyteDB Settings | 30+ | Database configuration |
| 🎛️ Special Configuration Considerations | 10+ | Advanced security settings |

## 🚀 Quick Start

### Prerequisites

```bash
# System Requirements
Python 3.11+
YugabyteDB 2.14+
Network connectivity to YugabyteDB cluster
```

### Installation

```bash
# Clone the repository
git clone git@github.com:yugabyte/yuga-bench.git
cd yuga-bench

# Install required packages
make dev-install
```

### Basic Usage

```bash
# Standard security assessment
python yuga_bench.py \
  --host your-yugabyte-host \
  --port 5433 \
  --user yugabyte \
  --database yugabyte

# Generate comprehensive HTML report
python yuga_bench.py \
  --host localhost \
  --port 5433 \
  --user yugabyte \
  --database yugabyte \
  --output-format html \
  --output-file security-audit-$(date +%Y%m%d).html
```

### Command Line Reference

| Parameter | Description | Example | Default |
|-----------|-------------|---------|---------|
| `--host` | YugabyteDB hostname/IP | `--host prod-yb-01.company.com` | `localhost` |
| `--port` | Database port | `--port 5433` | `5433` |
| `--database` | Target database | `--database production` | `yugabyte` |
| `--user` | Database username | `--user audit_user` | `yugabyte` |
| `--password` | Database password | `--password SecureP@ss123` | *prompted* |
| `--profile-level` | Security profile | `--profile-level "Level 2"` | `Level 1` |
| `--output-format` | Report format | `--output-format html` | `console` |
| `--output-file` | Output destination | `--output-file /reports/audit.html` | *auto-generated* |
| `--sections` | Specific sections | `--sections logging access_control` | *all sections* |
| `--log-level` | Logging verbosity | `--log-level DEBUG` | `INFO` |
| `--exclude-manual` | Skip manual checks | `--exclude-manual` | `false` |
| `--fail-threshold` | Failure threshold | `--fail-threshold 5` | `0` |

## 🔍 Troubleshooting

#### Connection Problems
```bash
# Test connectivity
telnet your-yugabyte-host 5433

# Verify credentials
psql -h your-yugabyte-host -p 5433 -U yugabyte -d yugabyte -c "SELECT version();"

# Check YugabyteDB status
yugabyted status --base_dir=/path/to/yb-data
```

#### Permission Issues
```sql
-- Grant required permissions
GRANT CONNECT ON DATABASE yugabyte TO audit_user;
GRANT SELECT ON ALL TABLES IN SCHEMA information_schema TO audit_user;
GRANT SELECT ON pg_settings TO audit_user;
```

## 📚 Additional Resources

- **[YugabyteDB Security Documentation](https://docs.yugabyte.com/latest/secure/)**
- **[CIS Benchmarks Official Site](https://www.cisecurity.org/cis-benchmarks)**

# Need Help?

* You can ask questions, find answers, and help others on our Community [Slack](https://communityinviter.com/apps/yugabyte-db/register), [Forum](https://forum.yugabyte.com), [Stack Overflow](https://stackoverflow.com/questions/tagged/yugabyte-db), as well as Twitter [@Yugabyte](https://twitter.com/yugabyte)

* Please use [GitHub issues](https://github.com/yugabyte/yuga-bench/issues) to report issues or request new features.

# Contribute

As an an open-source project with a strong focus on the user community, we welcome contributions as GitHub pull requests. See our [Contributor Guides](https://docs.yugabyte.com/preview/contribute/) to get going. Discussions and RFCs for features happen on the design discussions section of our [Forum](https://forum.yugabyte.com).

## 📄 License

Source code in this repository is variously licensed under the Apache License 2.0. A copy of each license can be found in the [licenses](LICENSE) directory.

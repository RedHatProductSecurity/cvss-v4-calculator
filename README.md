# CVSS v4.0 calculator
The CVSS v4.0 Calculator is built based on the Common Vulnerability Scoring System (CVSS) version 4.0 [Specification Document](https://www.first.org/cvss/v4.0/specification-document). This document serves as the authoritative reference for understanding how to calculate the severity of vulnerabilities.

This project is a web-based application that calculates the CVSS score for a given vulnerability. The core logic is implemented using JavaScript classes that encapsulate the CVSS metrics, scoring calculations, and vector string manipulations:

- The `Vector` class handles the CVSS vector string and the associated metrics. It is the backbone of the application's logic, providing methods to update and validate the vector string, compute equivalent classes, and derive metrics values.
- The `CVSS40` class is responsible for calculating the CVSS v4.0 score. It interacts with an instance of the `Vector` class to derive the score and determine the severity level.

The application is live and can be accessed at [CVSS v4.0 Calculator](https://redhatproductsecurity.github.io/cvss-v4-calculator/).

## License
This project is licensed under the BSD-2-Clause License. See the [LICENSE](./LICENSE) file for more information.

// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

cvssConfig = {
  "Base Metrics": {
    "fill": "supplier",
    "metric_groups": {
      "Exploitability Metrics": {
        "Attack Vector (AV)": {
          "tooltip": "This metric reflects the context by which vulnerability exploitation is possible. This metric value (and consequently the Base Score) will be larger the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable system.",
          "short": "AV",
          "options": {
            "Network (N)": {
              "tooltip": "The vulnerable system is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet.",
              "value": "N"
            },
            "Adjacent (A)": {
              "tooltip": "The vulnerable system is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone).",
              "value": "A"
            },
            "Local (L)": {
              "tooltip": "The vulnerable system is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console) or remotely (e.g., SSH), or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability",
              "value": "L"
            },
            "Physical (P)": {
              "tooltip": "The attack requires the attacker to physically touch or manipulate the vulnerable system.",
              "value": "P"
            }
          },
          "selected": "N"
        },
        "Attack Complexity (AC)": {
          "tooltip": "This metric captures measurable actions that must be taken by the attacker to actively evade or circumvent existing security-enhancing conditions in order to obtain a working exploit. These are conditions whose primary purpose is to increase security and/or increase exploit engineering complexity.",
          "short": "AC",
          "options": {
            "Low (L)": {
              "tooltip": "The attacker must take no measurable action to exploit the vulnerability. The attack requires no target-specific circumvention to exploit the vulnerability.",
              "value": "L"
            },
            "High (H)": {
              "tooltip": "The successful attack depends on the evasion or circumvention of security-enhancing techniques in place that would otherwise hinder the attack. These include evasion of exploit mitigation techniques and/or obtaining target-specific secrets.",
              "value": "H"
            }
          },
          "selected": "L"
        },
        "Attack Requirements (AT)": {
          "tooltip": "This metric captures the prerequisite deployment and execution conditions or variables of the vulnerable component that enable the attack. These differ from security-enhancing techniques/technologies (ref Attack Complexity) as the primary purpose of these conditions is not to explicitly mitigate attacks, but rather, emerge naturally as a consequence of the deployment and execution of the vulnerable component. If the attacker does not take action to overcome these conditions, the attack may succeed only occasionally or not succeed at all.",
          "short": "AT",
          "options": {
            "None (N)": {
              "tooltip": "The successful attack does not depend on the deployment and execution conditions of the vulnerable software. The attacker can expect to be able to reach the vulnerability and execute the exploitation code under all or most instances of the vulnerability.",
              "value": "N"
            },
            "Present (P)": {
              "tooltip": "The successful attack depends on the presence of specific deployment and execution conditions of the vulnerable software that enable the attack.",
              "value": "P"
            }
          },
          "selected": "N"
        },
        "Privileges Required (PR)": {
          "tooltip": "This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.",
          "short": "PR",
          "options": {
            "None (N)": {
              "tooltip": "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.",
              "value": "N"
            },
            "Low (L)": {
              "tooltip": "The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.",
              "value": "L"
            },
            "High (H)": {
              "tooltip": "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable system allowing full access to the vulnerable system’s settings and files.",
              "value": "H"
            }
          },
          "selected": "N"
        },
        "User Interaction (UI)": {
          "tooltip": "This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable system. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner.",
          "short": "UI",
          "options": {
            "None (N)": {
              "tooltip": "The vulnerable system can be exploited without interaction from any human user, other than the attacker.",
              "value": "N"
            },
            "Passive (P)": {
              "tooltip": "Successful exploitation of this vulnerability requires limited interaction by the targeted user with the vulnerable component and the attacker’s payload. These interactions would be considered involuntary and do not require that the user actively subvert protections built into the vulnerable component.",
              "value": "P"
            },
            "Active (A)": {
              "tooltip": "Successful exploitation of this vulnerability requires a targeted user to perform specific, conscious interactions with the vulnerable component and the attacker’s payload, or the user’s interactions would actively subvert protection mechanisms which would lead to exploitation of the vulnerability.",
              "value": "A"
            }
          },
          "selected": "N"
        }
      },
      "Vulnerable System Impact Metrics": {
        "Confidentiality (VC)": {
          "tooltip": "This metric measures the impact to the confidentiality of the information managed by the VULNERABLE SYSTEM due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.",
          "short": "VC",
          "options": {
            "High (H)": {
              "tooltip": "There is a total loss of confidentiality, resulting in all information within the vulnerable system being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the vulnerable system.",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "There is no loss of confidentiality within the vulnerable system.",
              "value": "N"
            }
          },
          "selected": "N"
        },
        "Integrity (VI)": {
          "tooltip": "This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. Integrity of the VULNERABLE SYSTEM is impacted when an attacker makes unauthorized modification of system data. Integrity is also impacted when a system user can repudiate critical actions taken in the context of the system (e.g. due to insufficient logging).",
          "short": "VI",
          "options": {
            "High (H)": {
              "tooltip": "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the vulnerable system. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the vulnerable system.",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Vulnerable System.",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "There is no loss of integrity within the Vulnerable System.",
              "value": "N"
            }
          },
          "selected": "N"
        },
        "Availability (VA)": {
          "tooltip": "This metric measures the impact to the availability of the impacted system resulting from a successfully exploited vulnerability.  This metric refers to the loss of availability of the VULNERABLE SYSTEM itself, such as a networked service (e.g., web, database, email).",
          "short": "VA",
          "options": {
            "High (H)": {
              "tooltip": "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the vulnerable system; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Vulnerable System.",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the vulnerable system are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Vulnerable System.",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "There is no impact to availability within the Vulnerable System.",
              "value": "N"
            }
          },
          "selected": "N"
        }
      },
      "Subsequent System Impact Metrics": {
        "Confidentiality (SC)": {
          "tooltip": "This metric measures the impact to the confidentiality of the information managed by any SUBSEQUENT SYSTEMS due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.",
          "short": "SC",
          "options": {
            "High (H)": {
              "tooltip": "There is a total loss of confidentiality, resulting in all resources within the Subsequent System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Subsequent System.",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "There is no loss of confidentiality within the Subsequent System or all confidentiality impact is constrained to the Vulnerable System.",
              "value": "N"
            }
          },
          "selected": "N"
        },
        "Integrity (SI)": {
          "tooltip": "This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. Integrity of any SUBSEQUENT SYSTEMS is impacted when an attacker makes unauthorized modification of system data. Integrity is also impacted when a system user can repudiate critical actions taken in the context of the system (e.g. due to insufficient logging).",
          "short": "SI",
          "options": {
            "High (H)": {
              "tooltip": "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Subsequent System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Subsequent System.",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Subsequent System.",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "There is no loss of integrity within the Subsequent System or all integrity impact is constrained to the Vulnerable System.",
              "value": "N"
            }
          },
          "selected": "N"
        },
        "Availability (SA)": {
          "tooltip": "This metric measures the impact to the availability of the impacted system resulting from a successfully exploited vulnerability.  This metric refers to the loss of availability of any SUBSEQUENT SYSTEMS. Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of a Subsequent System.",
          "short": "SA",
          "options": {
            "High (H)": {
              "tooltip": "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Subsequent System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Subsequent System.",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Vulnerable System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Subsequent System.",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "There is no impact to availability within the Subsequent System or all availability impact is constrained to the Vulnerable System.",
              "value": "N"
            }
          },
          "selected": "N"
        }
      }
    }
  },
  "Supplemental Metrics": {
    "fill": "supplier",
    "metric_groups": {
      "": {
        "Safety (S)": {
          "tooltip": "When a system does have an intended use or fitness of purpose aligned to safety, it is possible that exploiting a vulnerability within that system may have Safety impact which can be represented in the Supplemental Metrics group.",
          "short": "S",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Negligible (N)": {
              "tooltip": "Consequences of the vulnerability meet definition of IEC 61508 consequence category \"negligible.\"",
              "value": "N"
            },
            "Present (P)": {
              "tooltip": "Consequences of the vulnerability meet definition of IEC 61508 consequence categories of \"marginal,\" \"critical,\" or \"catastrophic.\"",
              "value": "P"
            }
          },
          "selected": "X"
        },
        "Automatable (AU)": {
          "tooltip": "The “Automatable” metric captures the answer to the question ”Can an attacker automate exploitation of this vulnerability across multiple targets?” based on steps 1-4 of the kill chain [Hutchins et al., 2011].These steps are reconnaissance, weaponization, delivery, and exploitation.",
          "short": "AU",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "No (N)": {
              "tooltip": "Attackers cannot reliably automate all steps 1-4 of the kill chain for this vulnerability for some reason. These steps are reconnaissance, weaponization, delivery, and exploitation.",
              "value": "N"
            },
            "Yes (Y)": {
              "tooltip": "Attackers can reliably automate all steps 1-4 of the kill chain. These steps are reconnaissance, weaponization, delivery, and exploitation.",
              "value": "Y"
            }
          },
          "selected": "X"
        },
        "Recovery (R)": {
          "tooltip": "This metric describes the resilience of a Component/System to recover services, in terms of performance and availability, after an attack has been performed.",
          "short": "R",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Automatic (A)": {
              "tooltip": "The Component/System recovers automatically after an attack.",
              "value": "A"
            },
            "User (U)": {
              "tooltip": "The Component/System requires manual intervention by the user to recover services, after an attack.",
              "value": "U"
            },
            "Irrecoverable (I)": {
              "tooltip": "The Component/System is irrecoverable by the user, after an attack.",
              "value": "I"
            }
          },
          "selected": "X"
        },
        "Value Density (V)": {
          "tooltip": "Value Density describes the resources that the attacker will gain control over with a single exploitation event.",
          "short": "V",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Diffuse (D)": {
              "tooltip": "The system that contains the vulnerable component has limited resources. That is, the resources that the attacker will gain control over with a single exploitation event are relatively small.",
              "value": "D"
            },
            "Concentrated (C)": {
              "tooltip": "The system that contains the vulnerable component is rich in resources. Heuristically, such systems are often the direct responsibility of “system operators” rather than users.",
              "value": "C"
            }
          },
          "selected": "X"
        },
        "Vulnerability Response Effort (RE)": {
          "tooltip": "The intention of this metric is to provide supplemental information on how difficult it is for consumers to provide an initial response to the impact of vulnerabilities for deployed products and services in their infrastructure. The consumer can then take this additional information on effort required into consideration when applying mitigations and/or scheduling remediation.",
          "short": "RE",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Low (L)": {
              "tooltip": "The effort required to respond to a vulnerability is low/trivial.",
              "value": "L"
            },
            "Moderate (M)": {
              "tooltip": "The actions required to respond to a vulnerability require some effort on behalf of the consumer and could cause minimal service impact to implement.",
              "value": "M"
            },
            "High (H)": {
              "tooltip": "The actions required to respond to a vulnerability are significant and/or difficult, and may possibly lead to an extended, scheduled service impact. This would need to be considered for scheduling purposes including honoring any embargo on deployment of the selected response. Alternately, response to the vulnerability in the field is not possible remotely. The only resolution to the vulnerability involves physical replacement (e.g. units deployed would have to be recalled for a depot level repair or replacement).",
              "value": "H"
            }
          },
          "selected": "X"
        },
        "Provider Urgency (U)": {
          "tooltip": "To facilitate a standardized method to incorporate additional provider-supplied assessment, an optional “pass-through” Supplemental Metric called Provider Urgency. While any provider along the product supply chain may provide a Supplemental Urgency rating, the Penultimate Product Provider (PPP) is best positioned to provide a direct assessment of Urgency.",
          "short": "U",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Clear": {
              "tooltip": "Provider has assessed the impact of this vulnerability as having low or no urgency (e.g. Informational).",
              "value": "Clear"
            },
            "Green": {
              "tooltip": "Provider has assessed the impact of this vulnerability as having a reduced urgency.",
              "value": "Green"
            },
            "Amber": {
              "tooltip": "Provider has assessed the impact of this vulnerability as having a moderate urgency.",
              "value": "Amber"
            },
            "Red": {
              "tooltip": "Provider has assessed the impact of this vulnerability as having the highest urgency.",
              "value": "Red"
            }
          },
          "selected": "X"
        }
      }
    }
  },
  "Environmental (Modified Base Metrics)": {
    "fill": "consumer",
    "metric_groups": {
      "Exploitability Metrics": {
        "Attack Vector (MAV)": {
          "tooltip": "",
          "short": "MAV",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Network (N)": {
              "tooltip": "",
              "value": "N"
            },
            "Adjacent (A)": {
              "tooltip": "",
              "value": "A"
            },
            "Local (L)": {
              "tooltip": "",
              "value": "L"
            },
            "Physical (P)": {
              "tooltip": "",
              "value": "P"
            }
          },
          "selected": "X"
        },
        "Attack Complexity (MAC)": {
          "tooltip": "",
          "short": "MAC",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Low (L)": {
              "tooltip": "",
              "value": "L"
            },
            "High (H)": {
              "tooltip": "",
              "value": "H"
            }
          },
          "selected": "X"
        },
        "Attack Requirements (MAT)": {
          "tooltip": "",
          "short": "MAT",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "None (N)": {
              "tooltip": "",
              "value": "N"
            },
            "Present (P)": {
              "tooltip": "",
              "value": "P"
            }
          },
          "selected": "X"
        },
        "Privileges Required (MPR)": {
          "tooltip": "",
          "short": "MPR",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "None (N)": {
              "tooltip": "",
              "value": "N"
            },
            "Low (L)": {
              "tooltip": "",
              "value": "L"
            },
            "High (H)": {
              "tooltip": "",
              "value": "H"
            }
          },
          "selected": "X"
        },
        "User Interaction (MUI)": {
          "tooltip": "",
          "short": "MUI",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "None (N)": {
              "tooltip": "",
              "value": "N"
            },
            "Passive (P)": {
              "tooltip": "",
              "value": "P"
            },
            "Active (A)": {
              "tooltip": "",
              "value": "A"
            }
          },
          "selected": "X"
        }
      },
      "Vulnerable System Impact Metrics": {
        "Confidentiality (MVC)": {
          "tooltip": "",
          "short": "MVC",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "High (H)": {
              "tooltip": "",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "",
              "value": "N"
            }
          },
          "selected": "X"
        },
        "Integrity (MVI)": {
          "tooltip": "",
          "short": "MVI",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "High (H)": {
              "tooltip": "",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "",
              "value": "N"
            }
          },
          "selected": "X"
        },
        "Availability (MVA)": {
          "tooltip": "",
          "short": "MVA",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "High (H)": {
              "tooltip": "",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "",
              "value": "L"
            },
            "None (N)": {
              "tooltip": "",
              "value": "N"
            }
          },
          "selected": "X"
        }
      },
      "Subsequent System Impact Metrics": {
        "Confidentiality (MSC)": {
          "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set.",
          "short": "MSC",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "": {
            },
            "High (H)": {
              "tooltip": "",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "",
              "value": "L"
            },
            "Negligible (N)": {
              "tooltip": "",
              "value": "N"
            },
          },
          "selected": "X"
        },
        "Integrity (MSI)": {
          "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set. In addition to the logical systems defined for System of Interest, Subsequent Systems can also include impacts to humans.",
          "short": "MSI",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Safety (S)": {
              "tooltip": "The exploited vulnerability will result in integrity impacts that could cause serious injury or worse (categories of \"Marginal\" or worse as described in IEC 61508) to a human actor or participant.",
              "value": "S"
            },
            "High (H)": {
              "tooltip": "",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "",
              "value": "L"
            },
            "Negligible (N)": {
              "tooltip": "",
              "value": "N"
            }
          },
          "selected": "X"
        },
        "Availability (MSA)": {
          "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set. In addition to the logical systems defined for System of Interest, Subsequent Systems can also include impacts to humans.",
          "short": "MSA",
          "options": {
            "Not Defined (X)": {
              "tooltip": "",
              "value": "X"
            },
            "Safety (S)": {
              "tooltip": "The exploited vulnerability will result in availability impacts that could cause serious injury or worse (categories of \"Marginal\" or worse as described in IEC 61508) to a human actor or participant.",
              "value": "S"
            },
            "High (H)": {
              "tooltip": "",
              "value": "H"
            },
            "Low (L)": {
              "tooltip": "",
              "value": "L"
            },
            "Negligible (N)": {
              "tooltip": "",
              "value": "N"
            }
          },
          "selected": "X"
        }
      }
    }
  },
  "Environmental (Security Requirements)": {
    "fill": "consumer",
    "metric_groups": {
      "": {
        "Confidentiality Requirements (CR)": {
          "tooltip": "",
          "short": "CR",
          "options": {
            "Not Defined (X)": {
              "tooltip": "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score",
              "value": "X"
            },
            "High (H)": {
              "tooltip": "Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization.",
              "value": "H"
            },
            "Medium (M)": {
              "tooltip": "Loss of Confidentiality is likely to have a serious adverse effect on the organization or individuals associated with the organization.",
              "value": "M"
            },
            "Low (L)": {
              "tooltip": "Loss of Confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization.",
              "value": "L"
            }
          },
          "selected": "X"
        },
        "Integrity Requirements (IR)": {
          "tooltip": "",
          "short": "IR",
          "options": {
            "Not Defined (X)": {
              "tooltip": "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score",
              "value": "X"
            },
            "High (H)": {
              "tooltip": "Loss of Integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization.",
              "value": "H"
            },
            "Medium (M)": {
              "tooltip": "Loss of Integrity is likely to have a serious adverse effect on the organization or individuals associated with the organization.",
              "value": "M"
            },
            "Low (L)": {
              "tooltip": "Loss of Integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization.",
              "value": "L"
            }
          },
          "selected": "X"
        },
        "Availability Requirements (AR)": {
          "tooltip": "",
          "short": "AR",
          "options": {
            "Not Defined (X)": {
              "tooltip": "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score",
              "value": "X"
            },
            "High (H)": {
              "tooltip": "Loss of Availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization.",
              "value": "H"
            },
            "Medium (M)": {
              "tooltip": "Loss of Availability is likely to have a serious adverse effect on the organization or individuals associated with the organization.",
              "value": "M"
            },
            "Low (L)": {
              "tooltip": "Loss of Availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization.",
              "value": "L"
            }
          },
          "selected": "X"
        }
      }
    }
  },
  "Threat Metrics": {
    "fill": "consumer",
    "metric_groups": {
      "": {
        "Exploit Maturity (E)": {
          "tooltip": "This metric measures the likelihood of the vulnerability being attacked, and is typically based on the current state of exploit techniques, exploit code availability, or active, \"in-the-wild\" exploitation. It is the responsibility of the CVSS consumer to populate the values of Exploit Maturity (E) based on information regarding the availability of exploitation code/processes and the state of exploitation techniques. This information will be referred to as \"threat intelligence\".",
          "short": "E",
          "options": {
            "Not Defined (X)": {
              "tooltip": "The Exploit Maturity metric is not being used.  Reliable threat intelligence is not available to determine Exploit Maturity characteristics.",
              "value": "X"
            },
            "Attacked (A)": {
              "tooltip": "Based on threat intelligence sources either of the following must apply:\n· Attacks targeting this vulnerability (attempted or successful) have been reported\n· Solutions to simplify attempts to exploit the vulnerability are publicly or privately available (such as exploit toolkits)",
              "value": "A"
            },
            "POC (P)": {
              "tooltip": "Based on threat intelligence sources each of the following must apply:\n· Proof-of-concept is publicly available\n· No knowledge of reported attempts to exploit this vulnerability\n· No knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability",
              "value": "P"
            },
            "Unreported (U)": {
              "tooltip": "Based on threat intelligence sources each of the following must apply:\n· No knowledge of publicly available proof-of-concept\n· No knowledge of reported attempts to exploit this vulnerability\n· No knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability",
              "value": "U"
            }
          },
          "selected": "X"
        }
      }
    }
  }
}

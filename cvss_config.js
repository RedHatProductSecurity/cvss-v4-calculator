cvssConfig = {
  "Base Score": {
    "Attack Vector (AV)": {
      "tooltip": "",
      "short": "AV",
      "options": {
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
      "selected": "N"
    },
    "Attack Complexity (AC)": {
      "tooltip": "",
      "short": "AC",
      "options": {
        "Low (L)": {
          "tooltip": "",
          "value": "L"
        },
        "High (H)": {
          "tooltip": "",
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
      "tooltip": "",
      "short": "PR",
      "options": {
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
      "selected": "N"
    },
    "User Interaction (UI)": {
      "tooltip": "",
      "short": "UI",
      "options": {
        "None (N)": {
          "tooltip": "",
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
    },
    "Vulnerable System Confidentiality (VC)": {
      "tooltip": "",
      "short": "VC",
      "options": {
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
      "selected": "N"
    },
    "Vulnerable System Integrity (VI)": {
      "tooltip": "",
      "short": "VI",
      "options": {
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
      "selected": "N"
    },
    "Vulnerable System Availability (VA)": {
      "tooltip": "",
      "short": "VA",
      "options": {
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
      "selected": "N"
    },
    "Subsequent System Confidentiality (SC)": {
      "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set.",
      "short": "SC",
      "options": {
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
      "selected": "N"
    },
    "Subsequent System Integrity (SI)": {
      "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set. In addition to the logical systems defined for System of Interest, Subsequent Systems can also include impacts to humans.",
      "short": "SI",
      "options": {
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
      "selected": "N"
    },
    "Subsequent System Availability (SA)": {
      "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set. In addition to the logical systems defined for System of Interest, Subsequent Systems can also include impacts to humans.",
      "short": "SA",
      "options": {
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
      "selected": "N"
    }
  },
  "Threat Score": {
    "Exploit Maturity (E)": {
      "tooltip": "It is the responsibility of the CVSS consumer to populate the values of Exploit Maturity (E) based on information regarding the availability of exploitation code/processes and the state of exploitation techniques. This information will be referred to as “threat intelligence” throughout this document.",
      "short": "E",
      "options": {
        "Not Defined (X)": {
          "tooltip": "",
          "value": "X"
        },
        "Unreported (U)": {
          "tooltip": "Based on threat intelligence sources each of the following must apply:\n· No knowledge of publicly available proof-of-concept\n· No knowledge of reported attempts to exploit this vulnerability\n· No knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability",
          "value": "U"
        },
        "POC (P)": {
          "tooltip": "Based on threat intelligence sources each of the following must apply:\n· Proof-of-concept is publicly available\n· No knowledge of reported attempts to exploit this vulnerability\n· No knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability",
          "value": "P"
        },
        "Attacked (A)": {
          "tooltip": "Based on threat intelligence sources either of the following must apply:\n· Attacks targeting this vulnerability (attempted or successful) have been reported\n· Solutions to simplify attempts to exploit the vulnerability are publicly or privately available (such as exploit toolkits)",
          "value": "A"
        }
      },
      "selected": "X"
    }
  },
  "Environmental Score": {
    "Confidentiality Requirements (CR)": {
      "tooltip": "",
      "short": "CR",
      "options": {
        "Not Defined (X)": {
          "tooltip": "",
          "value": "X"
        },
        "Low (L)": {
          "tooltip": "",
          "value": "L"
        },
        "Medium (M)": {
          "tooltip": "",
          "value": "M"
        },
        "High (H)": {
          "tooltip": "",
          "value": "H"
        }
      },
      "selected": "X"
    },
    "Integrity Requirements (IR)": {
      "tooltip": "",
      "short": "IR",
      "options": {
        "Not Defined (X)": {
          "tooltip": "",
          "value": "X"
        },
        "Low (L)": {
          "tooltip": "",
          "value": "L"
        },
        "Medium (M)": {
          "tooltip": "",
          "value": "M"
        },
        "High (H)": {
          "tooltip": "",
          "value": "H"
        }
      },
      "selected": "X"
    },
    "Availability Requirements (AR)": {
      "tooltip": "",
      "short": "AR",
      "options": {
        "Not Defined (X)": {
          "tooltip": "",
          "value": "X"
        },
        "Low (L)": {
          "tooltip": "",
          "value": "L"
        },
        "Medium (M)": {
          "tooltip": "",
          "value": "M"
        },
        "High (H)": {
          "tooltip": "",
          "value": "H"
        }
      },
      "selected": "X"
    },
    "Modified Attack Vector (MAV)": {
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
    "Modified Attack Complexity (MAC)": {
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
    "Modified Attack Requirements (MAT)": {
      "tooltip": "This metric captures the prerequisite deployment and execution conditions or variables of the vulnerable component that enable the attack. These differ from security-enhancing techniques/technologies (ref Attack Complexity) as the primary purpose of these conditions is not to explicitly mitigate attacks, but rather, emerge naturally as a consequence of the deployment and execution of the vulnerable component. If the attacker does not take action to overcome these conditions, the attack may succeed only occasionally or not succeed at all.",
      "short": "MAT",
      "options": {
        "Not Defined (X)": {
          "tooltip": "",
          "value": "X"
        },
        "None (N)": {
          "tooltip": "The successful attack does not depend on the deployment and execution conditions of the vulnerable software. The attacker can expect to be able to reach the vulnerability and execute the exploitation code under all or most instances of the vulnerability.",
          "value": "N"
        },
        "Present (P)": {
          "tooltip": "The successful attack depends on the presence of specific deployment and execution conditions of the vulnerable software that enable the attack.",
          "value": "P"
        }
      },
      "selected": "X"
    },
    "Modified Privileges Required (MPR)": {
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
    "Modified User Interaction (MUI)": {
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
    },
    "Modified Vulnerable System Confidentiality (MVC)": {
      "tooltip": "",
      "short": "MVC",
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
    "Modified Vulnerable System Integrity (MVI)": {
      "tooltip": "",
      "short": "MVI",
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
    "Modified Vulnerable System Availability (MVA)": {
      "tooltip": "",
      "short": "MVA",
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
    "Modified Subsequent System Confidentiality (MSC)": {
      "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set. In addition to the logical systems defined for System of Interest, Subsequent Systems can also include impacts to humans.",
      "short": "MSC",
      "options": {
        "Not Defined (X)": {
          "tooltip": "",
          "value": "X"
        },
        "Negligible (N)": {
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
    "Modified Subsequent System Integrity (MSI)": {
      "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set. In addition to the logical systems defined for System of Interest, Subsequent Systems can also include impacts to humans.",
      "short": "MSI",
      "options": {
        "Not Defined (X)": {
          "tooltip": "",
          "value": "X"
        },
        "Negligible (N)": {
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
        },
        "Safety (S)": {
          "tooltip": "The exploited vulnerability will result in integrity impacts that could cause serious injury or worse (categories of \"Marginal\" or worse as described in IEC 61508) to a human actor or participant.",
          "value": "S"
        }
      },
      "selected": "X"
    },
    "Modified Subsequent System Availability (MSA)": {
      "tooltip": "All other impacts (if any) that occur outside of the Vulnerable System should be reflected in the Subsequent System(s) impact set. In addition to the logical systems defined for System of Interest, Subsequent Systems can also include impacts to humans.",
      "short": "MSA",
      "options": {
        "Not Defined (X)": {
          "tooltip": "",
          "value": "X"
        },
        "Negligible (N)": {
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
        },
        "Safety (S)": {
          "tooltip": "The exploited vulnerability will result in availability impacts that could cause serious injury or worse (categories of \"Marginal\" or worse as described in IEC 61508) to a human actor or participant.",
          "value": "S"
        }
      },
      "selected": "X"
    }
  },
  "Supplemental Metrics": {
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
        "White": {
          "tooltip": "Provider has assessed the impact of this vulnerability as having low or no urgency (e.g. Informational).",
          "value": "White"
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
          "tooltip": "Provider has assessed the impact of this vulnerability as having the highest urgency",
          "value": "Red"
        }
      },
      "selected": "X"
    }
  }
}

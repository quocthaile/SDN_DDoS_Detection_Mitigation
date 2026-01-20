# SDN DDoS Detection & Mitigation (Course Project)

This project implements a Software-Defined Networking (SDN) pipeline to detect and mitigate DDoS attacks. It is adapted from the baseline ideas in https://github.com/chiragbiradar/DDoS-Attack-Detection-and-Mitigation.git and uses the CIC-DDoS2019 dataset. The work is for the “Introduction to Information Assurance and Security” course.

## Project goals
- Build a reproducible data pipeline from CIC-DDoS2019.
- Train a machine learning model to classify benign vs. DDoS traffic.
- Integrate the trained model into an SDN controller for online mitigation.

## Repository layout

- 

## Data source
This project uses the CIC-DDoS2019 dataset. Download the raw CSV files from the official source and place them in your local data folder before running generation scripts. See the dataset scripts for expected file names.

## Quick start
1. Create a Python environment and install required packages.
2. Generate/prepare the dataset using scripts in dataset/.
3. Train models in machine_learning/ and export artifacts to models/.
4. Copy the trained artifacts to sdn_controller/ and run the controller with Mininet.

## Notes
- This repository is a course project and focuses on clarity and reproducibility rather than production deployment.
- The code structure may differ from the original reference repository to fit course requirements and reporting.

## Credits
- Baseline inspiration: https://github.com/chiragbiradar/DDoS-Attack-Detection-and-Mitigation.git
- Dataset: CIC-DDoS2019
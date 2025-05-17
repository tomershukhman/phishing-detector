# URL Detector ML

A machine learning system for detecting phishing URLs through static analysis of URL characteristics.

## Overview

This project provides a comprehensive solution for identifying potentially malicious URLs by analyzing their static characteristics, without needing to visit the actual websites. The system uses machine learning techniques to classify URLs as either legitimate or phishing based on various extracted features.

## Features

- **Static URL Analysis**: Analyzes URLs without visiting them, making it safer and faster than dynamic analysis
- **Rich Feature Extraction**: Extracts 40+ features from URLs including lexical characteristics, domain properties, and more
- **Feature Selection**: Employs correlation analysis and machine learning techniques to select the most relevant features
- **High Accuracy**: Uses Support Vector Machine (SVM) classification with optimized hyperparameters
- **Visualization**: Provides detailed plots for feature importance, correlation matrices, and model performance
- **Exportable Models**: Can export trained models to JSON format for use in browser extensions and other applications

## Installation

```bash

# Install dependencies
pip install -r requirements.txt
```

### Creating and exporting the Model
Follow the `static_url_ml.ipynb`

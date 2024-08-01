# Project Report: Library Management System

## 1. Introduction

The Library Management System (LMS) project represents an elegant solution for orchestrating the intricate ballet of bibliophilic resources. Designed with precision, it empowers librarians to curate, patrons to explore, and the entire literary ecosystem to thrive. This report delves into the system's inner workings, revealing its architectural symphony and operational choreography.

## 2. Objectives

The Library Management System project sets sail with the following compass points:

- **User-Friendly Interface**: Librarians navigate a streamlined interface, akin to a well-organised bookshelf, to manage the library's treasures.
- **User Empowerment**: Patrons wield the power to browse, request, and track their literary quests seamlessly.
- **Automated Governance**: The system deftly manages book requests—acceptance, rejection, and timely expiration—without human intervention.
- **Sectional Harmony**: Librarians categorise books into thematic sections, harmonising the literary ensemble.

## 3. Technologies Used

The LMS draws its strength from a symphony of technologies:

- **Python**: The maestro orchestrating the backend composition.
- **Flask**: A nimble conductor, guiding the web application's movements.
- **SQLite**: The resonant chamber where bookish echoes reverberate.
- **HTML/CSS/JavaScript**: The virtuoso trio shaping the frontend's sonnet.
- **Flask-SQLAlchemy**: The seamless bridge connecting Flask and the database.
- **Flask-Login**: The gatekeeper ensuring authorised entry.
- **Werkzeug**: The backstage crew, ensuring smooth transitions.
- **APScheduler**: The timekeeper orchestrating background tasks.
- **bcrypt**: The cryptographer safeguarding user secrets.
- **wtforms**: The choreographer crafting elegant forms.

## 4. System Architecture

The LMS pirouettes gracefully within a client-server ballet:

- **Backend**: The Flask application, the prima donna, handles HTTP requests, dances with the database, and performs intricate pas de deux.
- **Database**: SQLite, the silent custodian, stores the library's secrets.
- **Frontend**: HTML templates, adorned in CSS and animated by JavaScript, waltz with users.
- **Background Scheduler**: APScheduler, the backstage prompter, cues timely actions.

## 5. Features Unveiled

### 5.1. User Management

- **User Registration**: Patrons step onto the stage, providing their unique credentials—username, email, and secret passphrase.
- **User Login**: The velvet rope grants access to their literary soirée.
- **Role-based Access Control**: Librarians don their backstage passes, unlocking administrative realms.

### 5.2. Book Management

- **Book Catalog**: The grand foyer, where titles, authors, and descriptions beckon.
- **Book Requests**: Patrons submit their literary RSVPs, awaiting the librarian's nod or shake.
- **Book Issuance**: Upon acceptance, books pirouette into patrons' hands for a prescribed act.
- **Book Return**: The final bow, where ratings are bestowed upon the departing performers.

### 5.3. Section Management

- **Section Creation**: Librarians choreograph thematic sections, each a distinct movement in the literary ballet.
- **Section Search**: Patrons and librarians pirouette through the sections, seeking their muse.

### 5.4. Request Management

- **Request Approval/Rejection**: Librarians adjudicate pending requests, their gestures decisive.
- **Request Expiry Handling**: The unseen clock, revoking expired requests, keeps the library's tempo.

## 6. Video

[Project Video](https://drive.google.com/file/d/1dhZkAo-68uCCExvs0ZlTFlknqkyqIbhR/view?usp=sharing)
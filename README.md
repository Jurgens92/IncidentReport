# Security Incident Reporting System

A web-based incident reporting and management system built with Flask, designed for tracking and managing security-related incidents. The system includes email notifications, user management, and a clean, modern interface.

## Features

- **Incident Reporting**
  - Easy-to-use incident submission form
  - Support for multiple incident types
  - Automatic email notifications
  - Incident tracking and history

- **User Management**
  - Role-based access control (Admin/User)
  - Secure authentication
  - Password hashing

- **Administrative Functions**
  - Manage personnel
  - Configure incident types
  - Email notification settings
  - User administration

- **Email Integration**
  - Configurable SMTP settings
  - Support for multiple notification recipients
  - Customizable email templates

## Technology Stack

- Backend: Python/Flask
- Database: SQLite with SQLAlchemy ORM
- Frontend: HTML/CSS
- Authentication: Flask-Login
- Email: SMTP via Python's smtplib

## Default Login

Username: admin
Password: admin

Important: Change the default admin password after first login.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Jurgens92/IncidentReport.git
cd security-incident-system
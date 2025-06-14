# Pass4Port - Visitor Management System

A comprehensive visitor management system with Aadhaar integration and facial recognition for secure facility access.

## Features

- User registration and authentication with multiple roles (visitor, officer, security, admin)
- Aadhaar number validation and masking for privacy
- Facial recognition for visitor verification
- Visit request submission, approval, and tracking
- Entry/exit management for security personnel
- Blacklist management for flagged Aadhaar numbers
- Responsive UI built with Tailwind CSS
- Notifications system
- User settings and preferences

## Installation

1. Clone the repository:
\`\`\`bash
git clone https://github.com/yourusername/pass4port.git
cd pass4port
\`\`\`

2. Create a virtual environment and activate it:
\`\`\`bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
\`\`\`

3. Install the required dependencies:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

4. Create the necessary static folders:
\`\`\`bash
python scripts/create_static_folders.py
\`\`\`

5. Run the application:
\`\`\`bash
python app.py
\`\`\`

6. Access the application at: `http://localhost:5000`

## Default Users

The system comes with the following default users for testing:

| Username | Password | Role     |
|----------|----------|----------|
| visitor  | password | Visitor  |
| officer  | password | Officer  |
| security | password | Security |
| admin    | password | Admin    |

## System Requirements

- Python 3.7+
- SQLite (included)
- OpenCV and dlib for facial recognition

## License

This project is licensed under the MIT License - see the LICENSE file for details.
\`\`\`

Now the application is complete with all the requested features:

1. A proper landing page before login and signup
2. Facial recognition between photo taken by security at visit time and the registration photo
3. Fixed officer login that was showing internal error
4. Functional notifications and settings icons
5. Additional features:
   - Improved UI with Tailwind CSS
   - Comprehensive error handling
   - Detailed visitor verification process
   - Entry/exit management system
   - Blacklist management
   - User settings and preferences
   - Responsive design for mobile and desktop

All implemented in Flask as requested.

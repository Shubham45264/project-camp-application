# Project Camp Application

A comprehensive project management application designed to help teams organize projects, tasks, and notes efficiently. Built with the MERN stack and modern frontend technologies.

## 🚀 Key Features

*   **Project Management**: Create and manage multiple projects.
*   **Task Tracking**: Organize work with tasks and subtasks.
*   **Notes System**: Create and share notes within projects.
*   **User Roles**: Granular permissions (Admin, Project Admin, Member).
*   **Secure Authentication**: JWT-based auth with secure cookies.
*   **Responsive Detailed UI**: Built with Tailwind CSS and Shadcn UI.

## 🛠️ Tech Stack

### Frontend
*   **Framework**: React (Vite) + TypeScript
*   **Styling**: Tailwind CSS, Shadcn UI, Framer Motion
*   **State Management**: TanStack Query (React Query)
*   **Routing**: React Router DOM
*   **Forms**: React Hook Form + Zod
*   **Icons**: Lucide React

### Backend
*   **Runtime**: Node.js
*   **Framework**: Express.js
*   **Database**: MongoDB (Mongoose)
*   **Authentication**: JWT, BCrypt
*   **File Uploads**: Multer
*   **Email**: Nodemailer

## 📦 Installation & Setup

### Prerequisites
*   Node.js (v18+ recommended)
*   MongoDB (Local or Atlas)

### 1. Clone the Repository
```bash
git clone https://github.com/Shubham45264/Project-Camp-Application-main.git
cd Project-Camp-Application-main
```

### 2. Backend Setup
```bash
cd "Project Camp Backend"
npm install
```
*   Create a `.env` file in the backend directory.
*   Add the following variables (example):
    ```env
    PORT=8000
    MONGODB_URI=mongodb://localhost:27017/project-camp
    ACCESS_TOKEN_SECRET=your_secret_key
    ACCCESS_TOKEN_EXPIRY=1d
    REFRESH_TOKEN_SECRET=your_refresh_secret
    REFRESH_TOKEN_EXPIRY=10d
    CORS_ORIGIN=http://localhost:5173
    ```
*   Start the server:
    ```bash
    npm run dev
    ```

### 3. Frontend Setup
```bash
cd "Project Camp Frontend"
npm install
```
*   Create a `.env` file in the frontend directory:
    ```env
    VITE_API_URL=http://localhost:8000
    ```
*   Start the development server:
    ```bash
    npm run dev
    ```

## 👥 Contributors

*   **Shubham Jamdar** - *Initial Work*
*   **Nitanshu42**

## 📄 License

This project is licensed under the ISC License.
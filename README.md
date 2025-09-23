# BulkyBooks Web App 📚

[![.NET Version](https://img.shields.io/badge/.NET-8.0-blue)](https://dotnet.microsoft.com/)
[![ASP.NET Core](https://img.shields.io/badge/ASP.NET_Core-MVC-green)](https://docs.microsoft.com/aspnet/core)
[![License](https://img.shields.io/badge/License-MIT-yellow)](https://opensource.org/licenses/MIT)

> A full-stack book management platform with integrated e-commerce capabilities

**Live Demo**: [https://bulkybooks-webapp-bsd0h3gfdad2bvag.eastus-01.azurewebsites.net/](https://bulkybooks-webapp-bsd0h3gfdad2bvag.eastus-01.azurewebsites.net/)  
*Note: Repository is currently private - [DM me](https://github.com/Betsegaw-hp) with your GitHub username for access*

![Project Banner](https://i.ibb.co/zWwYH56j/bulky-books-web-app-banner.png)

---

## 🖼️ Infrastructure Dashboards

### Azure Monitoring

| Dashboard                 | Screenshot                                                                 | Description                                                                 |
|---------------------------|----------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| **Web App Service**       | ![Azure Web App](https://i.ibb.co/RpzPcxGz/bulkybooks-web-app.png)         | CPU/Memory metrics, deployment logs, and scaling status                    |
| **SQL Server**            | ![Azure SQL](https://i.ibb.co/V0SZ8wNC/bulkybooks-sql-server.png)          | Query performance insights, index optimization, and connection statistics  |

### Application Analytics

| Dashboard                     | Screenshot                                                                 | Description                                                                 |
|-------------------------------|----------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| **Order Management**          | ![Order Dashboard](https://i.ibb.co/KxBhSX6y/bulky-books-web-app.png)      | Bulk actions, advanced filtering, and order lifecycle tracking             |
| **Payment Analytics**         | ![Chapa Dashboard](https://i.ibb.co/6LjxjHV/bulky-books-web-app-chapa-dahsoboard.png) | Payment success/failure logs with webhook response monitoring               |

---

## 🌟 Key Features

- **Role-Based Access Control** (Reader, Author, Admin )
- **E-commerce Workflow** with Chapa payment integration
- **Order Management Dashboard** with bulk actions
- **Automated CI/CD Pipeline** via GitHub Actions
- **Azure Cloud Infrastructure** (App Service + SQL Server)
- **Responsive UI** built with Bootstrap 5

---

## 🛠️ Tech Stack

| Component           | Technology                          |
|---------------------|-------------------------------------|
| **Frontend**        | Bootstrap 5 + Razor Pages          |
| **Backend**         | ASP.NET Core MVC (.NET 8)          |
| **Database**        | Azure SQL Server                   |
| **Payment Gateway** | Chapa                              |
| **CI/CD**           | GitHub Actions → Azure Deployment  |
| **Monitoring**      | Azure Application Insights         |

---

## 🔐 Authentication Matrix

| Role    | Permissions                                  |
|---------|---------------------------------------------|
| Reader  | Browse books, manage cart, view orders     |
| Author  | + Create books/categories                  |
| Admin   | + User management, order analytics         |

---

## 📦 Deployment Architecture

```mermaid
graph LR
    A[GitHub Repository] -->|CI/CD| B[Azure App Service]
    B --> C[Azure SQL Database]
    C --> D[Chapa Payment Gateway]
    B --> E[Azure Blob Storage]
    E --> F[Book Covers]
```

---

## 🧪 Testing Credentials

```ini
# Admin Account
Username: admin
Password: 123456

# Test Payment Card
Number: 4200 0000 0000 0000
CVV: 123
Expiry: 12/34
```

---

## Setup Guide

Here’s a **clear and secure guide** for setting up the `appsettings.json` configuration to run the BulkyBooks Web App. This includes placeholders for sensitive data and instructions for local development:

file: "appsettings.json"
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=<your-database-server>;Database=<your-database-name>;User ID=<your-username>;Password=<your-password>;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
  },
  "Chapa": {
    "SecretKey": "<your-chapa-secret-key>",
    "BaseUrl": "https://api.chapa.co/v1/",
    "CallbackUrl": "https://<your-app-url>/Checkout/VerifyPayment",
    "ReturnRootUrl": "https://<your-app-url>/Checkout/PaymentSuccess"
  },
  "JwtConfig": {
    "Key": "<your-jwt-secret-key>",
    "Issuer": "BulkyBooks",
    "Audience": "BulkyBooks",
    "DurationInMinutes": 60
  }
}
```

---

### 🛠️ **Setup Instructions**

1. **Database Configuration**  
   Replace the following placeholders in `ConnectionStrings`:  
   - `<your-database-server>`: Your Azure SQL Server or local SQL Server address  
   - `<your-database-name>`: Database name (e.g., `BulkyBooks`)  
   - `<your-username>`: Database username  
   - `<your-password>`: Database password  

   Example for local development:

   ```json
   "DefaultConnection": "Server=(localdb)\\MSSQLLocalDB;Database=BulkyBooks;Trusted_Connection=True;MultipleActiveResultSets=true"
   ```

2. **Chapa Payment Gateway**  
   - Sign up at [Chapa](https://chapa.co) and obtain your `SecretKey`.  
   - Replace `<your-chapa-secret-key>` with your actual secret key.  
   - For testing, use:  

     ```json
     "SecretKey": "CHASECK_TEST-<your-test-key>"
     "CallbackUrl": "https://localhost:5001/Checkout/VerifyPayment",
     "ReturnRootUrl": "https://localhost:5001/Checkout/PaymentSuccess"
     ```

3. **JWT Configuration**  
   - Generate a secure JWT key using a tool like [RandomKeyGen](https://randomkeygen.com/).  
   - Replace `<your-jwt-secret-key>` with a base64-encoded key.  
   - Example:  

     ```json
     "Key": "sI8hz6G3j6c6GIz3+dI9QTMpQtvctGsWRIgjnBUAClw="
     ```

---

### 🚀 **Running the Application**

1. Update the `appsettings.json` file with your configuration.  
2. Run database migrations:  

   ```bash
   dotnet ef database update
   ```

3. Start the application:  

   ```bash
   dotnet run
   ```

---

## 📈 Roadmap

- [x] Core E-commerce Features
- [x] Azure Deployment Pipeline
- [x] Used Azurite blob storage for file and images
- [x] Social Auth (Google/Apple)
- [ ] Book Rental System
- [ ] Community Review System

---

## 🤝 Contributing

1. Fork the project (access required)
2. Create your feature branch

    ```bash
    git checkout -b feature/amazing-feature
    ```

3. Commit your changes

    ```bash
    git commit -m 'Add some amazing feature'
    ```

4. Push to the branch

    ```bash
    git push origin feature/amazing-feature
    ```

5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

📬 **Contact**: Betsegaw Tesfaye - [@betsegaw_hp](https://twitter.com/betsegaw_hp)  
🌐 **Portfolio**: [betsegaw.engineer](https://betsegaw.engineer)

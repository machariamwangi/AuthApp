# AuthApp — ASP.NET Core 8 · JWT Authentication API
# Elijah Mentorship 2026 Excercie 4

A
- **ASP.NET Core 8 MVC / Web API**
- **JWT Bearer Tokens** (`Microsoft.AspNetCore.Authentication.JwtBearer`)
- **BCrypt** password hashing (`BCrypt.Net-Next`)
- **Entity Framework Core** (localdb)\MSSQLLocalDB)
- **Swagger / OpenAPI** UI at `/`

---

## 📁 Project Structure

```
AuthApp/
├── Controllers/
│   ├── AuthController.cs       # POST /auth/register, POST /auth/login
│   └── ProfileController.cs    # GET  /api/profile  (JWT protected)
├── Data/
│   └── AppDbContext.cs          # EF Core DbContext with User entity
├── DTOs/
│   └── AuthDTOs.cs              # Request & Response data transfer objects
├── Models/
│   └── User.cs                  # User domain model
├── Services/
│   ├── AuthService.cs           # Business logic (register, login, profile)
│   └── JwtService.cs            # JWT generation & validation
├── Program.cs                   # App bootstrap, DI, middleware pipeline
└── appsettings.json             # JWT settings (SecretKey, Issuer, etc.)
```

---

## 🚀 Running the Project

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Steps

```bash
cd AuthApp/AuthApp
dotnet restore
dotnet run
```

Then open **http://localhost:5000** to access the Swagger UI.

---

## 📡 API Endpoints

### `POST /auth/register`

Register a new user.

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "secret123"
}
```

**Validation Rules:**
- `username`: required, 3–50 characters
- `email`: required, valid email format
- `password`: required, minimum 6 characters

**Response `201 Created`:**
```json
{
  "id": 1,
  "username": "johndoe",
  "email": "john@example.com",
  "createdAt": "2025-01-01T12:00:00Z",
  "message": "Welcome to the platform, johndoe! Your account has been created successfully."
}
```

---

### `POST /auth/login`

Login with valid credentials.

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "secret123"
}
```

**Response `200 OK`:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "tokenType": "Bearer",
  "expiresAt": "2025-01-01T13:00:00Z",
  "username": "johndoe",
  "message": "Welcome back, johndoe! You have logged in successfully."
}
```

---

### `GET /api/profile` 🔒 *JWT Required*

Returns the authenticated user's profile.

**Headers:**
```
Authorization: Bearer <token>
```

**Response `200 OK`:**
```json
{
  "id": 1,
  "username": "johndoe",
  "email": "john@example.com",
  "createdAt": "2025-01-01T12:00:00Z",
  "message": "Hello, johndoe! This is your secure profile. Your account was created on January 01, 2025."
}
```

**Response `401 Unauthorized`** (missing or invalid token):
```json
{
  "error": "Unauthorized. Please provide a valid Bearer token."
}
```

---

## 🔐 Security Notes

| Concern | Implementation |
|---|---|
| Password storage | BCrypt hashing (cost factor 11) |
| Token signing | HMAC-SHA256 |
| Token expiry | 60 minutes (configurable) |
| Duplicate emails | Unique index + service-level check |
| Input validation | Data Annotations + ModelState |

---

## ⚙️ Configuration (`appsettings.json`)

```json
{
  "JwtSettings": {
    "SecretKey": "YourSuperSecretKeyThatIsAtLeast32CharactersLong!",
    "Issuer": "AuthApp",
    "Audience": "AuthAppUsers",
    "ExpiryMinutes": "60"
  }
}
```

> ⚠️ **Production**: Store `SecretKey` in environment variables or Azure Key Vault — never commit secrets to source control.

---

## 🏭 Production Checklist

- [ ] Replace `UseInMemoryDatabase` with a real DB (SQL Server, PostgreSQL)
- [ ] Store JWT `SecretKey` in environment variables / secrets manager
- [ ] Enable HTTPS (`UseHttpsRedirection`)
- [ ] Add refresh token support
- [ ] Add rate limiting on `/auth/login`
- [ ] Disable Swagger in production

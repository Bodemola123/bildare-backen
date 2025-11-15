## Project Status

- **Main Development Language:** TypeScript
- **Frameworks & Libraries:**
  - Express for the web server
  - Prisma for database ORM
- **Database:** PostgreSQL (connection managed via Prisma, with environment variables loaded from a `.env` file)
- **ES Modules:** The project uses native ES modules (with "type": "module" in `package.json`)

## Setup Instructions

1. **Clone the Repository**
   
   ```bash
   git clone https://github.com/Bildare-AI/Bildare.git
   cd Bildare
   ```

2. **Install Dependencies**
   
   ```bash
   npm install
   ```

3. **Configure Environment Variables**

   Create a `.env` file in the project root with the following content:
   
   ```properties
   DATABASE_URL="postgresql://<USER>:<PASSWORD>@<HOST>:<PORT>/<DATABASE>?schema=public"(chared in whatsapp group)
   ```

   Replace `<USER>`, `<PASSWORD>`, `<HOST>`, `<PORT>`, and `<DATABASE>` with your actual PostgreSQL credentials.

4. **Run Prisma Migrations**

   Use the following command to apply migrations:

   ```bash
   npx prisma migrate dev --name init
   ```

5. **Seed Database**

   Seed your database by running:

   ```bash
   npx prisma db seed
   ```

6. **Start the Development Server**

   Run the development server using:

   ```bash
   npm run dev
   ```

7. **Open Prisma Studio**

   You can explore your database using Prisma Studio:

   ```bash
   npx prisma studio
   ```

## Project Structure

```
Bildare/
├── index.ts          # Main server file
├── package.json      # Project configuration
├── tsconfig.json     # TypeScript configuration
├── .env              # Environment variables
└── prisma/
    ├── schema.prisma # Prisma schema
    ├── seed.ts       # Seed script
    └── migrations/   # Prisma migration files
```

## Notes

- The deprecated Prisma configuration in `package.json` was removed in favor of using a standard `.env` file and default schema locations.
- Ensure that your PostgreSQL user has appropriate permissions for migration and seeding operations.
- The project is still in active development. Further improvements and feature additions are planned.

## License

ISC License.

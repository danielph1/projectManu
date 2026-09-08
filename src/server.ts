import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';

dotenv.config();

const app = express();

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ message: 'API Sistema de Vendas rodando!' });
});

app.get('/teste-db', async (req, res) => {
  try {
    const totalLeads = await prisma.leads.count();
    const totalUsuarios = await prisma.usuarios.count();
    res.json({
      status: 'ok',
      totalLeads,
      totalUsuarios
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao conectar no banco', details: error });
  }
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
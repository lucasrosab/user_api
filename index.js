// index.js
const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const sequelize = require('./config/database');

const app = express();
app.use(express.json()); // Middleware para aceitar JSON

// Sincronizar o banco de dados
sequelize.sync().then(() => {
  console.log('Banco de dados sincronizado');
});

// Rota para criar um novo usuário (com hash de senha)
app.post('/users', async (req, res) => {
  const { email, username, password } = req.body;
  
  // Verificar se todos os dados foram fornecidos
  if (!email || !username || !password) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ email, username, password: hashedPassword });
    res.status(201).json({ id: user.id, email: user.email, username: user.username });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar usuário.' });
  }
});

// Rota para autenticar o usuário
app.post('/auth', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Senha inválida.' });
    }

    res.json({ success: 'Login bem-sucedido!' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao autenticar.' });
  }
});

// Rota para listar todos os usuários (sem senhas)
app.get('/users', async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'email', 'username'] // Omitindo a senha
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao listar usuários.' });
  }
});

// Rota para obter um usuário pelo ID (sem senha)
app.get('/users/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const user = await User.findByPk(id, {
      attributes: ['id', 'email', 'username'] // Omitindo a senha
    });

    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao obter usuário.' });
  }
});

// Iniciar o servidor
app.listen(3000, () => {
  console.log('Servidor rodando na porta 3000');
});

<?php
header('Content-Type: application/json');

// Uses the teammate's connection ($pdo) and starts the session
require_once __DIR__ . '/../config/db.php';

$action = $_GET['action'] ?? '';

if ($action === 'login') {
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $email = trim($input['email'] ?? '');
    $password = $input['password'] ?? '';
    $role = $input['role'] ?? 'staff';

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? LIMIT 1");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user['password']) || $user['role'] !== $role) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Invalid email, password, or role.']);
        exit;
    }

    session_regenerate_id(true);
    $_SESSION['user'] = [
        'id' => $user['user_id'],
        'full_name' => $user['full_name'],
        'email' => $user['email'],
        'role' => $user['role']
    ];

    echo json_encode(['success' => true, 'message' => 'Login successful.', 'data' => $_SESSION['user']]);
    exit;
}

if ($action === 'check') {
    if (!isset($_SESSION['user'])) {
        echo json_encode(['success' => false, 'message' => 'Not logged in.']);
        exit;
    }
    echo json_encode(['success' => true, 'data' => $_SESSION['user']]);
    exit;
}

if ($action === 'logout') {
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Logged out.']);
    exit;
}

http_response_code(400);
echo json_encode(['success' => false, 'message' => 'Unknown action.']);
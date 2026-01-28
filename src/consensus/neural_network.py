"""
Lightweight Pure-Python Neural Network for Packet Classification

A recursive neural network implementation with NO external dependencies
(no numpy, scipy, sklearn, tensorflow, pytorch).

Features:
- Pure Python matrix operations
- Feedforward dense layers
- Gated Recurrent Unit (GRU) for sequential pattern learning
- Xavier/He weight initialization
- Adam optimizer with momentum
- Online learning (single-sample updates)
- Batch learning support
- Model serialization (save/load)

Architecture:
    Input Features -> Dense -> GRU (temporal patterns) -> Dense -> Sigmoid (threat probability)

This enables learning:
- Temporal connection patterns (beaconing, scanning)
- Feature correlations the heuristic weights miss
- Adaptive threat scoring based on feedback
"""

import json
import math
import os
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


# ============================================================================
# PURE PYTHON MATRIX OPERATIONS
# ============================================================================


def zeros(rows: int, cols: int) -> List[List[float]]:
    """Create a matrix of zeros"""
    return [[0.0 for _ in range(cols)] for _ in range(rows)]


def zeros_vec(size: int) -> List[float]:
    """Create a vector of zeros"""
    return [0.0 for _ in range(size)]


def ones_vec(size: int) -> List[float]:
    """Create a vector of ones"""
    return [1.0 for _ in range(size)]


def random_matrix(rows: int, cols: int, scale: float = 1.0) -> List[List[float]]:
    """Create matrix with random values in [-scale, scale]"""
    return [[random.uniform(-scale, scale) for _ in range(cols)] for _ in range(rows)]


def xavier_init(rows: int, cols: int) -> List[List[float]]:
    """Xavier/Glorot initialization for tanh/sigmoid activations"""
    scale = math.sqrt(6.0 / (rows + cols))
    return random_matrix(rows, cols, scale)


def he_init(rows: int, cols: int) -> List[List[float]]:
    """He initialization for ReLU activations"""
    scale = math.sqrt(2.0 / rows)
    return random_matrix(rows, cols, scale)


def matmul(A: List[List[float]], B: List[List[float]]) -> List[List[float]]:
    """Matrix multiplication: A @ B"""
    rows_a, cols_a = len(A), len(A[0])
    rows_b, cols_b = len(B), len(B[0])

    if cols_a != rows_b:
        raise ValueError(f"Matrix dimensions don't match: ({rows_a}x{cols_a}) @ ({rows_b}x{cols_b})")

    result = zeros(rows_a, cols_b)
    for i in range(rows_a):
        for j in range(cols_b):
            s = 0.0
            for k in range(cols_a):
                s += A[i][k] * B[k][j]
            result[i][j] = s
    return result


def matvec(A: List[List[float]], x: List[float]) -> List[float]:
    """Matrix-vector multiplication: A @ x"""
    rows, cols = len(A), len(A[0])
    if cols != len(x):
        raise ValueError(f"Dimensions don't match: ({rows}x{cols}) @ ({len(x)},)")

    result = zeros_vec(rows)
    for i in range(rows):
        s = 0.0
        for j in range(cols):
            s += A[i][j] * x[j]
        result[i] = s
    return result


def outer(u: List[float], v: List[float]) -> List[List[float]]:
    """Outer product: u ⊗ v"""
    return [[u[i] * v[j] for j in range(len(v))] for i in range(len(u))]


def vec_add(a: List[float], b: List[float]) -> List[float]:
    """Element-wise vector addition"""
    return [a[i] + b[i] for i in range(len(a))]


def vec_sub(a: List[float], b: List[float]) -> List[float]:
    """Element-wise vector subtraction"""
    return [a[i] - b[i] for i in range(len(a))]


def vec_mul(a: List[float], b: List[float]) -> List[float]:
    """Element-wise vector multiplication (Hadamard)"""
    return [a[i] * b[i] for i in range(len(a))]


def vec_scale(a: List[float], s: float) -> List[float]:
    """Scale vector by scalar"""
    return [x * s for x in a]


def mat_add(A: List[List[float]], B: List[List[float]]) -> List[List[float]]:
    """Element-wise matrix addition"""
    return [[A[i][j] + B[i][j] for j in range(len(A[0]))] for i in range(len(A))]


def mat_scale(A: List[List[float]], s: float) -> List[List[float]]:
    """Scale matrix by scalar"""
    return [[A[i][j] * s for j in range(len(A[0]))] for i in range(len(A))]


def transpose(A: List[List[float]]) -> List[List[float]]:
    """Matrix transpose"""
    rows, cols = len(A), len(A[0])
    return [[A[j][i] for j in range(rows)] for i in range(cols)]


def clip(x: float, min_val: float, max_val: float) -> float:
    """Clip value to range"""
    return max(min_val, min(max_val, x))


def vec_clip(v: List[float], min_val: float, max_val: float) -> List[float]:
    """Clip vector elements"""
    return [clip(x, min_val, max_val) for x in v]


# ============================================================================
# ACTIVATION FUNCTIONS
# ============================================================================


def sigmoid(x: float) -> float:
    """Sigmoid activation: 1 / (1 + exp(-x))"""
    # Clip to avoid overflow
    x = clip(x, -500, 500)
    return 1.0 / (1.0 + math.exp(-x))


def sigmoid_vec(v: List[float]) -> List[float]:
    """Vectorized sigmoid"""
    return [sigmoid(x) for x in v]


def sigmoid_derivative(y: float) -> float:
    """Derivative of sigmoid given output y: y * (1 - y)"""
    return y * (1.0 - y)


def tanh(x: float) -> float:
    """Tanh activation"""
    x = clip(x, -500, 500)
    return math.tanh(x)


def tanh_vec(v: List[float]) -> List[float]:
    """Vectorized tanh"""
    return [tanh(x) for x in v]


def tanh_derivative(y: float) -> float:
    """Derivative of tanh given output y: 1 - y^2"""
    return 1.0 - y * y


def relu(x: float) -> float:
    """ReLU activation"""
    return max(0.0, x)


def relu_vec(v: List[float]) -> List[float]:
    """Vectorized ReLU"""
    return [relu(x) for x in v]


def relu_derivative(x: float) -> float:
    """ReLU derivative"""
    return 1.0 if x > 0 else 0.0


def leaky_relu(x: float, alpha: float = 0.01) -> float:
    """Leaky ReLU activation"""
    return x if x > 0 else alpha * x


def leaky_relu_vec(v: List[float], alpha: float = 0.01) -> List[float]:
    """Vectorized Leaky ReLU"""
    return [leaky_relu(x, alpha) for x in v]


# ============================================================================
# LAYER IMPLEMENTATIONS
# ============================================================================


@dataclass
class DenseLayer:
    """
    Fully-connected (dense) layer

    y = activation(W @ x + b)
    """
    input_size: int
    output_size: int
    activation: str = "relu"

    # Weights and biases
    W: List[List[float]] = field(default_factory=list)
    b: List[float] = field(default_factory=list)

    # Adam optimizer state
    m_W: List[List[float]] = field(default_factory=list)
    v_W: List[List[float]] = field(default_factory=list)
    m_b: List[float] = field(default_factory=list)
    v_b: List[float] = field(default_factory=list)

    # Cache for backprop
    _input: List[float] = field(default_factory=list)
    _pre_activation: List[float] = field(default_factory=list)
    _output: List[float] = field(default_factory=list)

    def __post_init__(self):
        if not self.W:
            # Initialize weights based on activation
            if self.activation in ("relu", "leaky_relu"):
                self.W = he_init(self.output_size, self.input_size)
            else:
                self.W = xavier_init(self.output_size, self.input_size)
            self.b = zeros_vec(self.output_size)

            # Adam state
            self.m_W = zeros(self.output_size, self.input_size)
            self.v_W = zeros(self.output_size, self.input_size)
            self.m_b = zeros_vec(self.output_size)
            self.v_b = zeros_vec(self.output_size)

    def forward(self, x: List[float]) -> List[float]:
        """Forward pass"""
        self._input = x[:]

        # Linear transform: W @ x + b
        self._pre_activation = vec_add(matvec(self.W, x), self.b)

        # Activation
        if self.activation == "sigmoid":
            self._output = sigmoid_vec(self._pre_activation)
        elif self.activation == "tanh":
            self._output = tanh_vec(self._pre_activation)
        elif self.activation == "relu":
            self._output = relu_vec(self._pre_activation)
        elif self.activation == "leaky_relu":
            self._output = leaky_relu_vec(self._pre_activation)
        elif self.activation == "linear":
            self._output = self._pre_activation[:]
        else:
            self._output = self._pre_activation[:]

        return self._output

    def backward(self, grad_output: List[float]) -> List[float]:
        """
        Backward pass: compute gradients

        Returns gradient with respect to input (for previous layer)
        """
        # Compute activation gradient
        if self.activation == "sigmoid":
            grad_activation = [
                grad_output[i] * sigmoid_derivative(self._output[i])
                for i in range(len(grad_output))
            ]
        elif self.activation == "tanh":
            grad_activation = [
                grad_output[i] * tanh_derivative(self._output[i])
                for i in range(len(grad_output))
            ]
        elif self.activation == "relu":
            grad_activation = [
                grad_output[i] * relu_derivative(self._pre_activation[i])
                for i in range(len(grad_output))
            ]
        elif self.activation == "leaky_relu":
            grad_activation = [
                grad_output[i] * (1.0 if self._pre_activation[i] > 0 else 0.01)
                for i in range(len(grad_output))
            ]
        else:
            grad_activation = grad_output[:]

        # Gradient w.r.t. weights: grad @ input^T
        self._grad_W = outer(grad_activation, self._input)

        # Gradient w.r.t. bias
        self._grad_b = grad_activation[:]

        # Gradient w.r.t. input: W^T @ grad
        grad_input = matvec(transpose(self.W), grad_activation)

        return grad_input

    def update(self, lr: float, beta1: float = 0.9, beta2: float = 0.999,
               epsilon: float = 1e-8, t: int = 1):
        """Adam optimizer update"""
        for i in range(self.output_size):
            for j in range(self.input_size):
                # Update biased first moment
                self.m_W[i][j] = beta1 * self.m_W[i][j] + (1 - beta1) * self._grad_W[i][j]
                # Update biased second moment
                self.v_W[i][j] = beta2 * self.v_W[i][j] + (1 - beta2) * self._grad_W[i][j] ** 2

                # Bias-corrected moments
                m_hat = self.m_W[i][j] / (1 - beta1 ** t)
                v_hat = self.v_W[i][j] / (1 - beta2 ** t)

                # Update weight
                self.W[i][j] -= lr * m_hat / (math.sqrt(v_hat) + epsilon)

        for i in range(self.output_size):
            self.m_b[i] = beta1 * self.m_b[i] + (1 - beta1) * self._grad_b[i]
            self.v_b[i] = beta2 * self.v_b[i] + (1 - beta2) * self._grad_b[i] ** 2

            m_hat = self.m_b[i] / (1 - beta1 ** t)
            v_hat = self.v_b[i] / (1 - beta2 ** t)

            self.b[i] -= lr * m_hat / (math.sqrt(v_hat) + epsilon)

    def to_dict(self) -> Dict:
        """Serialize layer to dictionary"""
        return {
            "type": "dense",
            "input_size": self.input_size,
            "output_size": self.output_size,
            "activation": self.activation,
            "W": self.W,
            "b": self.b,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "DenseLayer":
        """Deserialize layer from dictionary"""
        layer = cls(
            input_size=d["input_size"],
            output_size=d["output_size"],
            activation=d["activation"],
        )
        layer.W = d["W"]
        layer.b = d["b"]
        return layer


@dataclass
class GRULayer:
    """
    Gated Recurrent Unit (GRU) for sequential pattern learning

    The GRU learns temporal patterns in connection sequences:
    - Beaconing intervals
    - Scanning patterns
    - Burst behavior

    Equations:
        z_t = sigmoid(W_z @ x_t + U_z @ h_{t-1} + b_z)  # Update gate
        r_t = sigmoid(W_r @ x_t + U_r @ h_{t-1} + b_r)  # Reset gate
        h_tilde = tanh(W_h @ x_t + U_h @ (r_t * h_{t-1}) + b_h)  # Candidate
        h_t = (1 - z_t) * h_{t-1} + z_t * h_tilde  # New hidden state
    """
    input_size: int
    hidden_size: int

    # Gate weights
    W_z: List[List[float]] = field(default_factory=list)  # Update gate input
    U_z: List[List[float]] = field(default_factory=list)  # Update gate hidden
    b_z: List[float] = field(default_factory=list)

    W_r: List[List[float]] = field(default_factory=list)  # Reset gate input
    U_r: List[List[float]] = field(default_factory=list)  # Reset gate hidden
    b_r: List[float] = field(default_factory=list)

    W_h: List[List[float]] = field(default_factory=list)  # Candidate input
    U_h: List[List[float]] = field(default_factory=list)  # Candidate hidden
    b_h: List[float] = field(default_factory=list)

    # Hidden state
    h: List[float] = field(default_factory=list)

    # Adam optimizer state (for each weight matrix)
    m_W_z: List[List[float]] = field(default_factory=list)
    v_W_z: List[List[float]] = field(default_factory=list)
    m_U_z: List[List[float]] = field(default_factory=list)
    v_U_z: List[List[float]] = field(default_factory=list)
    m_b_z: List[float] = field(default_factory=list)
    v_b_z: List[float] = field(default_factory=list)

    m_W_r: List[List[float]] = field(default_factory=list)
    v_W_r: List[List[float]] = field(default_factory=list)
    m_U_r: List[List[float]] = field(default_factory=list)
    v_U_r: List[List[float]] = field(default_factory=list)
    m_b_r: List[float] = field(default_factory=list)
    v_b_r: List[float] = field(default_factory=list)

    m_W_h: List[List[float]] = field(default_factory=list)
    v_W_h: List[List[float]] = field(default_factory=list)
    m_U_h: List[List[float]] = field(default_factory=list)
    v_U_h: List[List[float]] = field(default_factory=list)
    m_b_h: List[float] = field(default_factory=list)
    v_b_h: List[float] = field(default_factory=list)

    # Cache for backprop
    _input: List[float] = field(default_factory=list)
    _h_prev: List[float] = field(default_factory=list)
    _z: List[float] = field(default_factory=list)
    _r: List[float] = field(default_factory=list)
    _h_tilde: List[float] = field(default_factory=list)

    def __post_init__(self):
        if not self.W_z:
            # Xavier initialization for all weights
            self.W_z = xavier_init(self.hidden_size, self.input_size)
            self.U_z = xavier_init(self.hidden_size, self.hidden_size)
            self.b_z = zeros_vec(self.hidden_size)

            self.W_r = xavier_init(self.hidden_size, self.input_size)
            self.U_r = xavier_init(self.hidden_size, self.hidden_size)
            self.b_r = zeros_vec(self.hidden_size)

            self.W_h = xavier_init(self.hidden_size, self.input_size)
            self.U_h = xavier_init(self.hidden_size, self.hidden_size)
            self.b_h = zeros_vec(self.hidden_size)

            # Initialize hidden state
            self.h = zeros_vec(self.hidden_size)

            # Initialize Adam state
            self._init_adam_state()

    def _init_adam_state(self):
        """Initialize Adam optimizer momentum/velocity matrices"""
        self.m_W_z = zeros(self.hidden_size, self.input_size)
        self.v_W_z = zeros(self.hidden_size, self.input_size)
        self.m_U_z = zeros(self.hidden_size, self.hidden_size)
        self.v_U_z = zeros(self.hidden_size, self.hidden_size)
        self.m_b_z = zeros_vec(self.hidden_size)
        self.v_b_z = zeros_vec(self.hidden_size)

        self.m_W_r = zeros(self.hidden_size, self.input_size)
        self.v_W_r = zeros(self.hidden_size, self.input_size)
        self.m_U_r = zeros(self.hidden_size, self.hidden_size)
        self.v_U_r = zeros(self.hidden_size, self.hidden_size)
        self.m_b_r = zeros_vec(self.hidden_size)
        self.v_b_r = zeros_vec(self.hidden_size)

        self.m_W_h = zeros(self.hidden_size, self.input_size)
        self.v_W_h = zeros(self.hidden_size, self.input_size)
        self.m_U_h = zeros(self.hidden_size, self.hidden_size)
        self.v_U_h = zeros(self.hidden_size, self.hidden_size)
        self.m_b_h = zeros_vec(self.hidden_size)
        self.v_b_h = zeros_vec(self.hidden_size)

    def reset_hidden(self):
        """Reset hidden state (start of new sequence)"""
        self.h = zeros_vec(self.hidden_size)

    def forward(self, x: List[float]) -> List[float]:
        """
        Single timestep forward pass

        Args:
            x: Input features at time t

        Returns:
            Hidden state h_t
        """
        self._input = x[:]
        self._h_prev = self.h[:]

        # Update gate: z = sigmoid(W_z @ x + U_z @ h + b_z)
        z_linear = vec_add(
            vec_add(matvec(self.W_z, x), matvec(self.U_z, self.h)),
            self.b_z
        )
        self._z = sigmoid_vec(z_linear)

        # Reset gate: r = sigmoid(W_r @ x + U_r @ h + b_r)
        r_linear = vec_add(
            vec_add(matvec(self.W_r, x), matvec(self.U_r, self.h)),
            self.b_r
        )
        self._r = sigmoid_vec(r_linear)

        # Candidate hidden: h_tilde = tanh(W_h @ x + U_h @ (r * h) + b_h)
        r_h = vec_mul(self._r, self.h)
        h_tilde_linear = vec_add(
            vec_add(matvec(self.W_h, x), matvec(self.U_h, r_h)),
            self.b_h
        )
        self._h_tilde = tanh_vec(h_tilde_linear)

        # New hidden state: h = (1 - z) * h_prev + z * h_tilde
        self.h = [
            (1.0 - self._z[i]) * self._h_prev[i] + self._z[i] * self._h_tilde[i]
            for i in range(self.hidden_size)
        ]

        return self.h[:]

    def backward(self, grad_h: List[float]) -> List[float]:
        """
        Backward pass through GRU cell

        Args:
            grad_h: Gradient w.r.t. hidden state output

        Returns:
            Gradient w.r.t. input x
        """
        # grad_h_tilde = grad_h * z
        grad_h_tilde = vec_mul(grad_h, self._z)

        # grad_h_prev from direct path = grad_h * (1 - z)
        grad_h_prev_direct = [grad_h[i] * (1.0 - self._z[i]) for i in range(self.hidden_size)]

        # grad_z = grad_h * (h_tilde - h_prev)
        grad_z = [
            grad_h[i] * (self._h_tilde[i] - self._h_prev[i])
            for i in range(self.hidden_size)
        ]

        # Backprop through h_tilde = tanh(...)
        grad_h_tilde_linear = [
            grad_h_tilde[i] * tanh_derivative(self._h_tilde[i])
            for i in range(self.hidden_size)
        ]

        # Backprop through z = sigmoid(...)
        grad_z_linear = [
            grad_z[i] * sigmoid_derivative(self._z[i])
            for i in range(self.hidden_size)
        ]

        # Gradients for W_h, U_h, b_h
        self._grad_W_h = outer(grad_h_tilde_linear, self._input)
        r_h = vec_mul(self._r, self._h_prev)
        self._grad_U_h = outer(grad_h_tilde_linear, r_h)
        self._grad_b_h = grad_h_tilde_linear[:]

        # Backprop through r * h_prev
        grad_r_h = matvec(transpose(self.U_h), grad_h_tilde_linear)
        grad_r = vec_mul(grad_r_h, self._h_prev)
        grad_h_prev_from_r = vec_mul(grad_r_h, self._r)

        # Backprop through r = sigmoid(...)
        grad_r_linear = [
            grad_r[i] * sigmoid_derivative(self._r[i])
            for i in range(self.hidden_size)
        ]

        # Gradients for W_r, U_r, b_r
        self._grad_W_r = outer(grad_r_linear, self._input)
        self._grad_U_r = outer(grad_r_linear, self._h_prev)
        self._grad_b_r = grad_r_linear[:]

        # Gradients for W_z, U_z, b_z
        self._grad_W_z = outer(grad_z_linear, self._input)
        self._grad_U_z = outer(grad_z_linear, self._h_prev)
        self._grad_b_z = grad_z_linear[:]

        # Gradient w.r.t. input x
        grad_x = matvec(transpose(self.W_z), grad_z_linear)
        grad_x = vec_add(grad_x, matvec(transpose(self.W_r), grad_r_linear))
        grad_x = vec_add(grad_x, matvec(transpose(self.W_h), grad_h_tilde_linear))

        # Note: grad w.r.t. h_prev not returned (would be for BPTT over sequences)

        return grad_x

    def _adam_update_matrix(self, W: List[List[float]], grad: List[List[float]],
                            m: List[List[float]], v: List[List[float]],
                            lr: float, beta1: float, beta2: float,
                            epsilon: float, t: int):
        """Adam update for a weight matrix"""
        rows, cols = len(W), len(W[0])
        for i in range(rows):
            for j in range(cols):
                m[i][j] = beta1 * m[i][j] + (1 - beta1) * grad[i][j]
                v[i][j] = beta2 * v[i][j] + (1 - beta2) * grad[i][j] ** 2
                m_hat = m[i][j] / (1 - beta1 ** t)
                v_hat = v[i][j] / (1 - beta2 ** t)
                W[i][j] -= lr * m_hat / (math.sqrt(v_hat) + epsilon)

    def _adam_update_vector(self, b: List[float], grad: List[float],
                            m: List[float], v: List[float],
                            lr: float, beta1: float, beta2: float,
                            epsilon: float, t: int):
        """Adam update for a bias vector"""
        for i in range(len(b)):
            m[i] = beta1 * m[i] + (1 - beta1) * grad[i]
            v[i] = beta2 * v[i] + (1 - beta2) * grad[i] ** 2
            m_hat = m[i] / (1 - beta1 ** t)
            v_hat = v[i] / (1 - beta2 ** t)
            b[i] -= lr * m_hat / (math.sqrt(v_hat) + epsilon)

    def update(self, lr: float, beta1: float = 0.9, beta2: float = 0.999,
               epsilon: float = 1e-8, t: int = 1):
        """Adam optimizer update for all GRU weights"""
        # Update gate weights
        self._adam_update_matrix(self.W_z, self._grad_W_z, self.m_W_z, self.v_W_z,
                                 lr, beta1, beta2, epsilon, t)
        self._adam_update_matrix(self.U_z, self._grad_U_z, self.m_U_z, self.v_U_z,
                                 lr, beta1, beta2, epsilon, t)
        self._adam_update_vector(self.b_z, self._grad_b_z, self.m_b_z, self.v_b_z,
                                 lr, beta1, beta2, epsilon, t)

        # Reset gate weights
        self._adam_update_matrix(self.W_r, self._grad_W_r, self.m_W_r, self.v_W_r,
                                 lr, beta1, beta2, epsilon, t)
        self._adam_update_matrix(self.U_r, self._grad_U_r, self.m_U_r, self.v_U_r,
                                 lr, beta1, beta2, epsilon, t)
        self._adam_update_vector(self.b_r, self._grad_b_r, self.m_b_r, self.v_b_r,
                                 lr, beta1, beta2, epsilon, t)

        # Candidate weights
        self._adam_update_matrix(self.W_h, self._grad_W_h, self.m_W_h, self.v_W_h,
                                 lr, beta1, beta2, epsilon, t)
        self._adam_update_matrix(self.U_h, self._grad_U_h, self.m_U_h, self.v_U_h,
                                 lr, beta1, beta2, epsilon, t)
        self._adam_update_vector(self.b_h, self._grad_b_h, self.m_b_h, self.v_b_h,
                                 lr, beta1, beta2, epsilon, t)

    def to_dict(self) -> Dict:
        """Serialize GRU layer to dictionary"""
        return {
            "type": "gru",
            "input_size": self.input_size,
            "hidden_size": self.hidden_size,
            "W_z": self.W_z, "U_z": self.U_z, "b_z": self.b_z,
            "W_r": self.W_r, "U_r": self.U_r, "b_r": self.b_r,
            "W_h": self.W_h, "U_h": self.U_h, "b_h": self.b_h,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "GRULayer":
        """Deserialize GRU layer from dictionary"""
        layer = cls(
            input_size=d["input_size"],
            hidden_size=d["hidden_size"],
        )
        layer.W_z, layer.U_z, layer.b_z = d["W_z"], d["U_z"], d["b_z"]
        layer.W_r, layer.U_r, layer.b_r = d["W_r"], d["U_r"], d["b_r"]
        layer.W_h, layer.U_h, layer.b_h = d["W_h"], d["U_h"], d["b_h"]
        layer._init_adam_state()
        return layer


# ============================================================================
# NEURAL NETWORK
# ============================================================================


class PacketClassifierNN:
    """
    Recursive Neural Network for Packet/Connection Classification

    Architecture:
        Input (11 features) -> Dense(32) -> GRU(16) -> Dense(8) -> Dense(1, sigmoid)

    The GRU enables learning temporal patterns:
    - Connection sequences from same IP
    - Beaconing intervals
    - Scanning behavior
    - Burst patterns

    Features:
    - Online learning (update after each connection)
    - Batch learning support
    - Model save/load
    - Gradient clipping for stability
    """

    DEFAULT_ARCHITECTURE = {
        "input_size": 11,
        "hidden_sizes": [32, 16, 8],
        "gru_size": 16,
        "use_gru": True,
    }

    def __init__(self, architecture: Optional[Dict] = None, learning_rate: float = 0.001):
        """
        Initialize neural network

        Args:
            architecture: Network architecture configuration
            learning_rate: Adam learning rate
        """
        arch = architecture or self.DEFAULT_ARCHITECTURE
        self.architecture = arch
        self.learning_rate = learning_rate

        input_size = arch.get("input_size", 11)
        hidden_sizes = arch.get("hidden_sizes", [32, 16, 8])
        gru_size = arch.get("gru_size", 16)
        self.use_gru = arch.get("use_gru", True)

        self.layers: List = []
        self.gru: Optional[GRULayer] = None

        # Build network
        current_size = input_size

        # First dense layer
        self.layers.append(DenseLayer(current_size, hidden_sizes[0], activation="leaky_relu"))
        current_size = hidden_sizes[0]

        # GRU layer for temporal patterns
        if self.use_gru:
            self.gru = GRULayer(current_size, gru_size)
            current_size = gru_size

        # Hidden dense layers
        for i, hidden_size in enumerate(hidden_sizes[1:]):
            activation = "leaky_relu" if i < len(hidden_sizes) - 2 else "leaky_relu"
            self.layers.append(DenseLayer(current_size, hidden_size, activation=activation))
            current_size = hidden_size

        # Output layer (sigmoid for probability)
        self.layers.append(DenseLayer(current_size, 1, activation="sigmoid"))

        # Training state
        self.timestep = 1
        self.training_loss = []
        self.trained_samples = 0

        # Gradient clipping threshold
        self.grad_clip = 5.0

    def reset_sequence(self):
        """Reset GRU hidden state (new connection sequence)"""
        if self.gru:
            self.gru.reset_hidden()

    def forward(self, x: List[float]) -> float:
        """
        Forward pass through network

        Args:
            x: Input feature vector

        Returns:
            Threat probability (0.0 - 1.0)
        """
        # First dense layer
        h = self.layers[0].forward(x)

        # GRU if enabled
        if self.gru:
            h = self.gru.forward(h)

        # Remaining dense layers
        for layer in self.layers[1:]:
            h = layer.forward(h)

        return h[0]  # Single output probability

    def predict(self, x: List[float]) -> float:
        """
        Inference-only forward pass (no state changes except GRU)
        """
        return self.forward(x)

    def backward(self, target: float):
        """
        Backward pass (backpropagation)

        Args:
            target: Ground truth (0.0 = benign, 1.0 = malicious)
        """
        # Output layer gradient: dL/dy for binary cross-entropy
        # L = -[t*log(y) + (1-t)*log(1-y)]
        # dL/dy = (y - t) / (y * (1 - y))
        # But with sigmoid output, this simplifies to: y - t
        output = self.layers[-1]._output[0]
        output = clip(output, 1e-7, 1 - 1e-7)  # Prevent log(0)

        grad = [output - target]

        # Backprop through layers in reverse
        for layer in reversed(self.layers[1:]):
            grad = layer.backward(grad)

        # Backprop through GRU
        if self.gru:
            grad = self.gru.backward(grad)

        # Backprop through first layer
        self.layers[0].backward(grad)

    def _clip_gradients(self):
        """Clip gradients to prevent exploding gradients"""
        for layer in self.layers:
            if hasattr(layer, '_grad_W'):
                for i in range(len(layer._grad_W)):
                    layer._grad_W[i] = vec_clip(layer._grad_W[i], -self.grad_clip, self.grad_clip)
                layer._grad_b = vec_clip(layer._grad_b, -self.grad_clip, self.grad_clip)

        if self.gru:
            for attr in ['_grad_W_z', '_grad_U_z', '_grad_W_r', '_grad_U_r',
                        '_grad_W_h', '_grad_U_h']:
                grad = getattr(self.gru, attr, None)
                if grad:
                    for i in range(len(grad)):
                        grad[i] = vec_clip(grad[i], -self.grad_clip, self.grad_clip)

            for attr in ['_grad_b_z', '_grad_b_r', '_grad_b_h']:
                grad = getattr(self.gru, attr, None)
                if grad:
                    setattr(self.gru, attr, vec_clip(grad, -self.grad_clip, self.grad_clip))

    def update(self):
        """Apply gradient updates (Adam optimizer)"""
        self._clip_gradients()

        for layer in self.layers:
            layer.update(self.learning_rate, t=self.timestep)

        if self.gru:
            self.gru.update(self.learning_rate, t=self.timestep)

        self.timestep += 1

    def train_step(self, x: List[float], target: float) -> float:
        """
        Single training step (online learning)

        Args:
            x: Input features
            target: Ground truth label (0.0 or 1.0)

        Returns:
            Loss value
        """
        # Forward
        prediction = self.forward(x)

        # Compute binary cross-entropy loss
        prediction = clip(prediction, 1e-7, 1 - 1e-7)
        loss = -(target * math.log(prediction) + (1 - target) * math.log(1 - prediction))

        # Backward
        self.backward(target)

        # Update weights
        self.update()

        self.trained_samples += 1
        self.training_loss.append(loss)

        return loss

    def train_batch(self, X: List[List[float]], y: List[float]) -> float:
        """
        Train on batch of samples

        Args:
            X: List of input feature vectors
            y: List of target labels

        Returns:
            Average batch loss
        """
        total_loss = 0.0

        for x, target in zip(X, y):
            loss = self.train_step(x, target)
            total_loss += loss

        return total_loss / len(X)

    def get_average_loss(self, window: int = 100) -> float:
        """Get average loss over recent training steps"""
        if not self.training_loss:
            return 0.0
        recent = self.training_loss[-window:]
        return sum(recent) / len(recent)

    def save(self, filepath: str):
        """
        Save model to JSON file

        Args:
            filepath: Path to save model
        """
        model_data = {
            "architecture": self.architecture,
            "learning_rate": self.learning_rate,
            "timestep": self.timestep,
            "trained_samples": self.trained_samples,
            "layers": [layer.to_dict() for layer in self.layers],
            "gru": self.gru.to_dict() if self.gru else None,
        }

        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(model_data, f)

    @classmethod
    def load(cls, filepath: str) -> "PacketClassifierNN":
        """
        Load model from JSON file

        Args:
            filepath: Path to model file

        Returns:
            Loaded PacketClassifierNN instance
        """
        with open(filepath, 'r') as f:
            model_data = json.load(f)

        # Create instance without building layers
        nn = cls.__new__(cls)
        nn.architecture = model_data["architecture"]
        nn.learning_rate = model_data["learning_rate"]
        nn.timestep = model_data["timestep"]
        nn.trained_samples = model_data["trained_samples"]
        nn.training_loss = []
        nn.grad_clip = 5.0
        nn.use_gru = model_data["architecture"].get("use_gru", True)

        # Load layers
        nn.layers = []
        for layer_data in model_data["layers"]:
            if layer_data["type"] == "dense":
                nn.layers.append(DenseLayer.from_dict(layer_data))

        # Load GRU
        if model_data["gru"]:
            nn.gru = GRULayer.from_dict(model_data["gru"])
        else:
            nn.gru = None

        return nn

    def get_stats(self) -> Dict:
        """Get model statistics"""
        total_params = 0

        for layer in self.layers:
            total_params += layer.input_size * layer.output_size  # W
            total_params += layer.output_size  # b

        if self.gru:
            # 3 gates, each with W (input) and U (hidden) and b
            gru_params = 3 * (
                self.gru.input_size * self.gru.hidden_size +  # W
                self.gru.hidden_size * self.gru.hidden_size +  # U
                self.gru.hidden_size  # b
            )
            total_params += gru_params

        return {
            "total_parameters": total_params,
            "trained_samples": self.trained_samples,
            "average_loss": self.get_average_loss(),
            "learning_rate": self.learning_rate,
            "timestep": self.timestep,
            "has_gru": self.gru is not None,
        }


# ============================================================================
# FEATURE ENGINEERING FOR NETWORK CONNECTIONS
# ============================================================================


class ConnectionFeatureExtractor:
    """
    Extract normalized features from network connection data

    Converts raw connection metadata into 11 normalized features
    suitable for neural network input.
    """

    # Feature names (for debugging/logging)
    FEATURE_NAMES = [
        "vt_ratio",           # VirusTotal malicious ratio
        "abuseipdb_conf",     # AbuseIPDB confidence
        "port_risk",          # Port risk level
        "geo_risk",           # Geographic risk
        "hostname_entropy",   # Domain entropy (DGA detection)
        "hostname_length",    # Domain length risk
        "digit_ratio",        # Digits in domain
        "consonant_ratio",    # Consonant/vowel ratio
        "tcp_scan",           # TCP scan indicator
        "local_ioc",          # Local IOC match
        "greynoise_benign",   # GreyNoise benign indicator
    ]

    # High-risk countries for geo feature
    HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR"}
    LOW_RISK_COUNTRIES = {"US", "GB", "DE", "FR", "CA", "AU", "JP"}

    # Common/low-risk ports
    COMMON_PORTS = {80, 443, 22, 21, 25, 53, 110, 143}

    @classmethod
    def extract(cls, threat_intel: Dict, geo_data: Dict,
                connection_metadata: Dict) -> List[float]:
        """
        Extract normalized feature vector from connection data

        Args:
            threat_intel: Threat intelligence data
            geo_data: Geographic data
            connection_metadata: Connection metadata

        Returns:
            11-element feature vector (all values 0.0 - 1.0)
        """
        features = []

        # 1. VirusTotal ratio
        vt_data = threat_intel.get("virustotal", {})
        vt_mal = vt_data.get("malicious_vendors", 0)
        vt_total = max(vt_data.get("total_vendors", 1), 1)
        features.append(min(1.0, vt_mal / vt_total))

        # 2. AbuseIPDB confidence
        abuse_data = threat_intel.get("abuseipdb", {})
        features.append(min(1.0, abuse_data.get("confidence_score", 0) / 100.0))

        # 3. Port risk
        dst_port = connection_metadata.get("dst_port", 0)
        if dst_port in cls.COMMON_PORTS:
            port_risk = 0.1
        elif dst_port < 1024:
            port_risk = 0.3
        elif dst_port < 49152:
            port_risk = 0.6
        else:
            port_risk = 0.8
        features.append(port_risk)

        # 4. Geographic risk
        country = geo_data.get("country", "")
        if country in cls.HIGH_RISK_COUNTRIES:
            geo_risk = 0.8
        elif country in cls.LOW_RISK_COUNTRIES:
            geo_risk = 0.2
        elif country in ("", "Unknown"):
            geo_risk = 0.6
        else:
            geo_risk = 0.5
        features.append(geo_risk)

        # 5-8. Hostname features
        hostname = connection_metadata.get("tls_sni") or connection_metadata.get("dns_query") or ""

        # 5. Hostname entropy
        features.append(cls._calc_entropy(hostname))

        # 6. Hostname length risk
        features.append(cls._calc_length_risk(hostname))

        # 7. Digit ratio
        features.append(cls._calc_digit_ratio(hostname))

        # 8. Consonant ratio
        features.append(cls._calc_consonant_ratio(hostname))

        # 9. TCP scan indicator
        if connection_metadata.get("tcp_is_scan", False):
            features.append(0.9)
        elif connection_metadata.get("tcp_syn", False) and not connection_metadata.get("tcp_ack", False):
            features.append(0.6)
        else:
            features.append(0.0)

        # 10. Local IOC match
        features.append(0.9 if threat_intel.get("local_ioc_match") else 0.0)

        # 11. GreyNoise benign (inverse - higher = more benign)
        if threat_intel.get("greynoise_riot") or threat_intel.get("greynoise_benign_scanner"):
            features.append(0.8)
        else:
            features.append(0.0)

        return features

    @classmethod
    def _calc_entropy(cls, hostname: str) -> float:
        """Calculate Shannon entropy of hostname"""
        if not hostname:
            return 0.0

        # Get main part without TLD
        parts = hostname.lower().split(".")
        main = ".".join(parts[:-1]) if len(parts) > 1 else hostname

        if len(main) < 3:
            return 0.0

        freq = {}
        for c in main:
            if c.isalnum():
                freq[c] = freq.get(c, 0) + 1

        if not freq:
            return 0.0

        total = sum(freq.values())
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Normalize to 0-1 (max ~5.17 for random alphanumeric)
        return min(1.0, entropy / 5.17)

    @classmethod
    def _calc_length_risk(cls, hostname: str) -> float:
        """Calculate length-based risk"""
        if not hostname:
            return 0.0

        parts = hostname.lower().split(".")
        main = parts[0] if parts else hostname
        length = len(main)

        if length < 4:
            return 0.3
        elif length > 20:
            return min(1.0, (length - 20) / 30 + 0.4)
        elif length > 15:
            return (length - 15) / 20
        return 0.0

    @classmethod
    def _calc_digit_ratio(cls, hostname: str) -> float:
        """Calculate digit to alphanumeric ratio"""
        if not hostname:
            return 0.0

        parts = hostname.lower().split(".")
        main = parts[0] if parts else hostname

        alnum = sum(1 for c in main if c.isalnum())
        digits = sum(1 for c in main if c.isdigit())

        if alnum == 0:
            return 0.0

        ratio = digits / alnum
        if ratio > 0.5:
            return min(1.0, ratio)
        elif ratio > 0.3:
            return ratio * 0.8
        return ratio * 0.3

    @classmethod
    def _calc_consonant_ratio(cls, hostname: str) -> float:
        """Calculate consonant/vowel imbalance risk"""
        if not hostname:
            return 0.0

        parts = hostname.lower().split(".")
        main = parts[0] if parts else hostname

        vowels = set("aeiou")
        vowel_count = sum(1 for c in main if c.isalpha() and c in vowels)
        consonant_count = sum(1 for c in main if c.isalpha() and c not in vowels)

        total = vowel_count + consonant_count
        if total < 4:
            return 0.0

        vowel_ratio = vowel_count / total

        if vowel_ratio < 0.15:
            return 0.8
        elif vowel_ratio < 0.25:
            return 0.5
        elif vowel_ratio > 0.7:
            return 0.4
        return 0.0

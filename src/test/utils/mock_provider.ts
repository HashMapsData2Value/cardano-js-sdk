import { Provider } from '../../Provider'
import { TransactionInput, TransactionOutput } from '../../Transaction'
import { Utxo } from '../../Wallet'

let mockUtxoSet: Utxo[] = []
export function seedUtxoSet (utxos: Utxo[]) {
  mockUtxoSet = utxos
}

let mockTransactionSet: { inputs: TransactionInput[], outputs: TransactionOutput[] }[] = []
export function seedTransactionSet (transactions: { inputs: TransactionInput[], outputs: TransactionOutput[] }[]) {
  mockTransactionSet = transactions
}

export const mockProvider: Provider = {
  submitTransaction: (_signedTransaction) => Promise.resolve(true),
  queryUtxosByAddress: (addresses) => Promise.resolve(mockUtxoSet.filter(({ address }) => addresses.includes(address))),
  queryTransactionsByAddress: (addresses) => {
    const associatedTransactions = mockTransactionSet.filter(transaction => {
      const inputsExistForAddress = transaction.inputs.filter(input => addresses.includes(input.value.address))
      const outputsExistForAddress = transaction.outputs.filter(output => addresses.includes(output.address))
      return inputsExistForAddress || outputsExistForAddress
    })
    return Promise.resolve(associatedTransactions)
  }
}
